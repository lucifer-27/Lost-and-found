import os
import re
from hmac import compare_digest
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo.errors import DuplicateKeyError
from ..extensions import users_collection, limiter
from ..services.email_service import send_otp_email
from ..services.verification_service import (
    clear_email_verification,
    create_email_verification,
    get_email_verification,
    get_otp_expiry_minutes,
    get_otp_max_attempts,
    get_otp_resend_cooldown_seconds,
    get_resend_wait_seconds,
    verify_email_verification,
)

auth_bp = Blueprint("auth", __name__)

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
STAFF_SECRET = os.environ.get("STAFF_SECRET", "")
ROLE_CODE_PATTERN = re.compile(r"^[A-Za-z]+[^A-Za-z0-9\s]+[0-9]+$")


def _is_valid_role_code_format(code):
    return bool(ROLE_CODE_PATTERN.fullmatch(code or ""))


def _should_show_otp_on_screen():
    setting = os.environ.get("SHOW_OTP_ON_SCREEN", "").strip().lower()
    if setting in {"1", "true", "yes", "on"}:
        return True
    if setting in {"0", "false", "no", "off"}:
        return False
    return os.environ.get("ENV", "development").strip().lower() != "production"


def _set_login_session(user):
    session.permanent = True
    session["user"] = user["email"]
    session["user_id"] = str(user["_id"])
    session["role"] = user["role"]
    session["first_login"] = True


def _redirect_for_role(role):
    if role == "student":
        return redirect(url_for("student.student_dashboard"))
    if role == "staff":
        return redirect(url_for("staff.staff_dashboard"))
    return redirect(url_for("admin.admin_dashboard"))


def _start_email_verification(email, purpose, payload=None):
    otp, error = create_email_verification(email, purpose, payload=payload)
    if error:
        return False, error
    success, err_msg = send_otp_email(email, otp, purpose=purpose)
    if not success:
        clear_email_verification(email, purpose)
        return False, f"We could not send the verification email. Error: {err_msg}"
    
    # Show OTP on the verification screen for local testing only.
    if _should_show_otp_on_screen():
        session["debug_otp"] = otp
    else:
        session.pop("debug_otp", None)

    session["verification_email"] = email
    session["verification_purpose"] = purpose
    return True, None


def _verification_page_context():
    purpose = session.get("verification_purpose")
    email = session.get("verification_email")
    details = {
        "register": {
            "title": "Verify your email",
            "subtitle": "Enter the code we sent to finish creating your account.",
        },
        "login": {
            "title": "Verify your login",
            "subtitle": "Enter the code we sent to complete sign-in.",
        },
        "reset_password": {
            "title": "Enter OTP",
            "subtitle": "Enter the code we sent so you can reset your password.",
        },
    }
    context = details.get(purpose, details["register"]).copy()
    context["email"] = email
    context["expiry_minutes"] = get_otp_expiry_minutes()
    context["max_attempts"] = get_otp_max_attempts()
    context["resend_cooldown_seconds"] = get_otp_resend_cooldown_seconds()
    context["resend_wait_seconds"] = get_resend_wait_seconds(email, purpose) if email and purpose else 0
    context["debug_otp"] = session.get("debug_otp")
    return context


def _render_verification_page(error=None, success=None):
    return render_template("verify_otp.html", error=error, success=success, **_verification_page_context())


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def register():
    if "user" in session:
        return redirect(url_for("general.home"))
    if request.method == "POST":
        full_name = " ".join((request.form.get("full_name", "") or "").split())
        email = (request.form.get("email") or "").strip().lower()
        role = (request.form.get("role") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""
        admin_code = (request.form.get("admin_code") or "").strip()
        staff_code = (request.form.get("staff_code") or "").strip()

        if not full_name:
            return render_template("register.html", error="Full name is required")
        if password != confirm:
            return render_template("register.html", error="Passwords do not match")
        if not re.match(r"^[a-zA-Z0-9]+@[a-zA-Z0-9]+\.pdpu\.ac\.in$", email):
            return render_template("register.html", error="Use college email: 24bcp001@sot.pdpu.ac.in")
        if len(password) < 8 or not re.search(r"[a-zA-Z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[@#$%^&+=_!\-]", password):
            return render_template("register.html", error="Password must be 8+ chars with letters, numbers, and a special character (@, #, etc.)")
       
        # Admin check
        if role == "admin":
            if not _is_valid_role_code_format(admin_code):
                return render_template("register.html", error="Admin code must be in format letters + special character + numbers (e.g. admin@123)")
            if not ADMIN_SECRET or not _is_valid_role_code_format(ADMIN_SECRET):
                return render_template("register.html", error="Admin access code is not configured correctly.")
            if not compare_digest(admin_code, ADMIN_SECRET):
                return render_template("register.html", error="Invalid admin access code")

        # Staff check
        if role == "staff":
            if not _is_valid_role_code_format(staff_code):
                return render_template("register.html", error="Invalid staff access code. Code must be in format letters + special character + numbers (e.g. staff@123)")

        if users_collection.find_one({"email": email}):
            return render_template("register.html", error="Email already registered")

        payload = {
            "name": full_name,
            "full_name": full_name,
            "email": email,
            "role": role,
            "password_hash": generate_password_hash(password),
            "account_flagged": False,
        }
        started, error = _start_email_verification(email, "register", payload=payload)
        if not started:
            return render_template("register.html", error=error)

        return redirect(url_for("auth.verify_otp"))
    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if "user" in session:
        return redirect(url_for("general.home"))
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        role = (request.form.get("role") or "").strip()
        password = request.form.get("password") or ""
        user = users_collection.find_one({"email": email})
        if user and check_password_hash(user["password_hash"], password):
            if user["role"] != role:
                return render_template("login.html", error="Wrong role selected")

            # Check if there's already an active login verification for this email
            existing_verification = get_email_verification(email, "login")
            if existing_verification and existing_verification.get("expires_at") and existing_verification["expires_at"] > datetime.utcnow():
                # Reuse existing OTP if it's still valid and not in cooldown
                wait_seconds = get_resend_wait_seconds(email, "login")
                if wait_seconds <= 0:
                    session["verification_email"] = email
                    session["verification_purpose"] = "login"
                    return redirect(url_for("auth.verify_otp"))
                else:
                    return render_template("login.html", error=f"You already have an active login request. Please wait {wait_seconds} seconds before trying again, or check your email for the existing OTP.")

            # Create new verification if none exists or expired
            started, error = _start_email_verification(email, "login", payload={"role": role})
            if not started:
                return render_template("login.html", error=error)
            return redirect(url_for("auth.verify_otp"))
        return render_template("login.html", error="Invalid email or password")
    return render_template("login.html")


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("2 per minute")
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        user = users_collection.find_one({"email": email})
        if not user:
            return render_template("forgot_password.html", error="Email not found")
        started, error = _start_email_verification(email, "reset_password")
        if not started:
            return render_template("forgot_password.html", error=error)
        return redirect(url_for("auth.verify_otp"))
    return render_template("forgot_password.html")


@auth_bp.route("/verify-otp", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def verify_otp():
    verification_email = session.get("verification_email")
    verification_purpose = session.get("verification_purpose")
    if not verification_email or not verification_purpose:
        flash("Start the verification process again.", "error")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        otp = (request.form.get("otp") or "").strip()
        verification_record, error = verify_email_verification(verification_email, verification_purpose, otp)
        if error:
            return _render_verification_page(error=error)

        session.pop("verification_email", None)
        session.pop("verification_purpose", None)
        session.pop("debug_otp", None)

        if verification_purpose == "register":
            payload = verification_record.get("payload", {})
            if users_collection.find_one({"email": verification_email}):
                return render_template("login.html", error="This email is already registered. Please login.")
            payload["email_verified_at"] = datetime.utcnow()
            users_collection.insert_one(payload)
            return render_template("login.html", success="Email verified. Registration complete. Please login.")

        if verification_purpose == "login":
            user = users_collection.find_one({"email": verification_email})
            if not user:
                return render_template("login.html", error="User not found. Please login again.")
            _set_login_session(user)
            return _redirect_for_role(user["role"])

        if verification_purpose == "reset_password":
            session["password_reset_verified_email"] = verification_email
            return redirect(url_for("auth.reset_password"))

    return _render_verification_page()


@auth_bp.route("/resend-otp", methods=["POST"])
def resend_otp():
    verification_email = session.get("verification_email")
    verification_purpose = session.get("verification_purpose")
    if not verification_email or not verification_purpose:
        flash("Start the verification process again.", "error")
        return redirect(url_for("auth.login"))

    existing_record = get_email_verification(verification_email, verification_purpose)
    if not existing_record and verification_purpose == "register":
        session.pop("verification_email", None)
        session.pop("verification_purpose", None)
        return render_template("register.html", error="Your verification session expired. Please register again.")
    if not existing_record and verification_purpose == "login":
        session.pop("verification_email", None)
        session.pop("verification_purpose", None)
        return render_template("login.html", error="Your verification session expired. Please login again.")
    if not existing_record and verification_purpose == "reset_password":
        session.pop("verification_email", None)
        session.pop("verification_purpose", None)
        return render_template("forgot_password.html", error="Your verification session expired. Please request a new OTP again.")

    payload = existing_record.get("payload", {}) if existing_record else None
    started, error = _start_email_verification(verification_email, verification_purpose, payload=payload)
    if not started:
        return _render_verification_page(error=error)
    return _render_verification_page(success="A new OTP has been sent to your email.")


@auth_bp.route("/reset-password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def reset_password():
    verified_email = session.get("password_reset_verified_email")
    if not verified_email:
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        if password != confirm:
            return render_template("reset_password.html", error="Passwords do not match")
        if len(password) < 8 or not re.search(r"[a-zA-Z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[@#$%^&+=_!\-]", password):
            return render_template("reset_password.html", error="Password must be 8+ chars with letters, numbers, and a special character (@, #, etc.)")

        hashed = generate_password_hash(password)
        users_collection.update_one({"email": verified_email}, {"$set": {"password_hash": hashed}})
        flash("Password changed successfully. Please login.", "success")
        session.pop("password_reset_verified_email", None)
        return redirect(url_for("auth.login"))
    return render_template("reset_password.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("general.home"))
