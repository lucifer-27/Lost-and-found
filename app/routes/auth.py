import re
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from ..extensions import users_collection
from ..services.otp_service import generate_otp
from ..services.email_service import send_otp_email

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if "user" in session:
        return redirect(url_for("general.home"))
    if request.method == "POST":
        full_name = " ".join((request.form.get("full_name", "") or "").split())
        email = request.form.get("email")
        role = request.form.get("role")
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")
        admin_code = request.form.get("admin_code")
        staff_code = request.form.get("staff_code")

        if not full_name:
            return render_template("register.html", error="Full name is required")
        if password != confirm:
            return render_template("register.html", error="Passwords do not match")
        if not re.match(r"^[a-zA-Z0-9]+@[a-zA-Z0-9]+\.pdpu\.ac\.in$", email.lower()):
            return render_template("register.html", error="Use college email: 24bcp001@sot.pdpu.ac.in")
        if len(password) < 8 or not re.search(r"[a-zA-Z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[@#$%^&+=_!\-]", password):
            return render_template("register.html", error="Password must be 8+ chars with letters, numbers, and a special character (@, #, etc.)")
        if role == "admin" and not admin_code:
            return render_template("register.html", error="Invalid admin code")
        if role == "staff" and not staff_code:
            return render_template("register.html", error="Invalid staff code")

        if users_collection.find_one({"email": email}):
            return render_template("register.html", error="Email already registered")

        users_collection.insert_one({
            "name": full_name, "full_name": full_name, "email": email,
            "role": role, "password_hash": generate_password_hash(password),
            "account_flagged": False
        })
        return render_template("register.html", success="Registration successful! Please login.")
    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("general.home"))
    if request.method == "POST":
        email = request.form.get("email")
        role = request.form.get("role")
        password = request.form.get("password")
        user = users_collection.find_one({"email": email})
        if user and check_password_hash(user["password_hash"], password):
            if user["role"] != role:
                return render_template("login.html", error="Wrong role selected")
            session["user"] = user["email"]
            session["user_id"] = str(user["_id"])
            session["role"] = user["role"]
            session["first_login"] = True
            if role == "student":
                return redirect(url_for("student.student_dashboard"))
            elif role == "staff":
                return redirect(url_for("staff.staff_dashboard"))
            elif role == "admin":
                return redirect(url_for("admin.admin_dashboard"))
        return render_template("login.html", error="Invalid email or password")
    return render_template("login.html")


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = users_collection.find_one({"email": email})
        if not user:
            return render_template("forgot_password.html", error="Email not found")
        otp = generate_otp()
        session["reset_email"] = email
        session["otp"] = otp
        send_otp_email(email, otp)
        return redirect(url_for("auth.verify_otp"))
    return render_template("forgot_password.html")


@auth_bp.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        if request.form.get("otp") == session.get("otp"):
            return redirect(url_for("auth.reset_password"))
        return render_template("verify_otp.html", error="Invalid OTP")
    return render_template("verify_otp.html")


@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        hashed = generate_password_hash(request.form.get("password"))
        users_collection.update_one({"email": session.get("reset_email")}, {"$set": {"password_hash": hashed}})
        flash("Password changed successfully. Please login.", "success")
        session.pop("reset_email", None)
        session.pop("otp", None)
        return redirect(url_for("auth.login"))
    return render_template("reset_password.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("general.home"))
