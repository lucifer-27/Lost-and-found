import os
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- APP SETUP ----------------
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = "lostandfound_secret_key_123"

# auto reload templates
app.config["TEMPLATES_AUTO_RELOAD"] = True

# session settings
app.permanent_session_lifetime = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "campusfind.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ---------------- MODELS ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)   # student / staff / admin
    password_hash = db.Column(db.String(200), nullable=False)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="active")
    reported_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# create database
with app.app_context():
    db.create_all()

# ---------------- HOME ----------------
@app.route("/")
def home():
    items = Item.query.filter_by(status="active").order_by(Item.created_at.desc()).limit(4).all()
    return render_template("index.html", recent_items=items)

# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():

    if "user" in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        email = request.form.get("email")
        role = request.form.get("role")
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")
        admin_code = request.form.get("admin_code")

        # password match
        if password != confirm:
            return render_template("register.html", error="Passwords do not match")

        # PDPU email validation
        if not re.match(r"^[A-Za-z0-9]+@[A-Za-z0-9]+\.pdpu\.ac\.in$", email.lower()):
            return render_template("register.html", error="Use college email: rollno@dept.pdpu.ac.in")

        # protect admin creation
        if role == "admin":
            if admin_code != "campusadmin123":
                return render_template("register.html", error="Invalid admin code")

        # check duplicate
        existing = User.query.filter_by(email=email).first()
        if existing:
            return render_template("register.html", error="Email already registered")

        # create user
        hashed = generate_password_hash(password)

        user = User(
            email=email,
            role=role,
            password_hash=hashed
        )

        db.session.add(user)
        db.session.commit()

        return render_template("register.html", success="Registration successful! Please login.")

    return render_template("register.html")

# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if "user" in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        email = request.form.get("email")
        role = request.form.get("role")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):

            if user.role != role:
                return render_template("login.html", error="Wrong role selected")

            session["user"] = user.email
            session["user_id"] = user.id
            session["role"] = user.role

            if role == "student":
                return redirect(url_for("student"))
            elif role == "staff":
                return redirect(url_for("staff"))
            elif role == "admin":
                return redirect(url_for("admin"))

        return render_template("login.html", error="Invalid email or password")

    return render_template("login.html")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ---------------- DASHBOARDS ----------------
@app.route("/student")
def student():
    if "user" not in session or session.get("role") != "student":
        return redirect(url_for("login"))
    return render_template("student.html")

@app.route("/staff")
def staff():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))
    return render_template("staff.html")

# 🟣 ADMIN DASHBOARD
@app.route("/admin")
def admin():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    total_users = User.query.count()
    total_items = Item.query.count()
    active_items = Item.query.filter_by(status="active").count()

    return render_template(
        "admin.html",
        total_users=total_users,
        total_items=total_items,
        active_items=active_items
    )

# ---------------- ITEMS ----------------
@app.route("/items")
def items():
    items = Item.query.order_by(Item.created_at.desc()).all()
    return render_template("items.html", items=items)

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
