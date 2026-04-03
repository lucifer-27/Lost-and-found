import re
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from ..extensions import users_collection
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
    if not send_otp_email(email, otp, purpose=purpose):
        clear_email_verification(email, purpose)
        return False, "We could not send the verification email. Please try again."
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
    return context


def _render_verification_page(error=None, success=None):
    return render_template("verify_otp.html", error=error, success=success, **_verification_page_context())


@auth_bp.route("/register", methods=["GET", "POST"])
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
        if role == "admin" and not admin_code:
            return render_template("register.html", error="Invalid admin code")
        if role == "staff" and not staff_code:
            return render_template("register.html", error="Invalid staff code")

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
            started, error = _start_email_verification(email, "login", payload={"role": role})
            if not started:
                return render_template("login.html", error=error)
            return redirect(url_for("auth.verify_otp"))
        return render_template("login.html", error="Invalid email or password")
    return render_template("login.html")


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
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
