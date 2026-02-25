import os
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, static_folder="static")
app.secret_key = "lostandfound_secret_key_123"

# 30-day remember configuration
app.permanent_session_lifetime = timedelta(days=30)

# security (important)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Database config
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "campusfind.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join(basedir, "static", "uploads")

db = SQLAlchemy(app)

# ---------------- MODELS ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False) # student, staff, admin
    roll_no = db.Column(db.String(20), nullable=True)
    department = db.Column(db.String(50), nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    type = db.Column(db.String(20), nullable=False) # 'lost' or 'found'
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=True)
    location = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), default='active') # active, returned
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    student_name = db.Column(db.String(100), nullable=False)
    roll_no = db.Column(db.String(20), nullable=False)
    student_email = db.Column(db.String(120), nullable=False)
    proof_description = db.Column(db.Text, nullable=False)
    return_date = db.Column(db.String(20), nullable=False)
    return_time = db.Column(db.String(20), nullable=False)
    verified_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Initialize DB
with app.app_context():
    db.create_all()

# ---------------- HOME PAGE ----------------
@app.route("/")
def home():
    items = Item.query.filter_by(status='active').order_by(Item.created_at.desc()).limit(4).all()
    return render_template("index.html", recent_items=items)

# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if "user" in session:
        return redirect(url_for(session.get("role") or "home"))

    if request.method == "POST":
        full_name = request.form.get("full_name")
        email = request.form.get("email")
        role = request.form.get("role")
        roll_no = request.form.get("roll_no")
        department = request.form.get("department")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match")
        if not re.match(r".+@.+\.pdpu\.ac\.in$", email.lower()):
            return render_template("register.html", error="Use your college email ID")
        
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            return render_template("register.html", error="Email already registered")
        
        hashed_password = generate_password_hash(password)
        new_user = User(full_name=full_name, email=email, role=role, roll_no=roll_no, department=department, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template("register.html", success="Registration successful! You can now login.")
    return render_template("register.html")

# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        role = session.get("role")
        if role in ["student", "staff", "admin"]:
            return redirect(url_for(role))
        return redirect(url_for("home"))

    error = None
    if request.method == "POST":
        email = request.form.get("email")
        role_selected = request.form.get("role")
        password = request.form.get("password")
        remember = request.form.get("remember-me")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            if user.role != role_selected:
                return render_template("login.html", error="Invalid role specified for this user")
            
            session.permanent = True if remember else False
            session["user"] = user.email
            session["user_id"] = user.id
            session["role"] = user.role
            session["full_name"] = user.full_name

            return redirect(url_for(user.role))
        else:
            return render_template("login.html", error="Invalid email or password")

    return render_template("login.html", error=error)

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ---------------- DASHBOARDS ----------------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    role = session.get("role")
    return redirect(url_for(role))

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

@app.route("/admin")
def admin():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    
    total_reports = Item.query.count()
    pending_items = Item.query.filter_by(status='active').count()
    claims = Claim.query.count()
    users_count = User.query.count()
    
    pending_reports = Item.query.filter_by(status='active').order_by(Item.created_at.desc()).limit(10).all()
    all_users = User.query.order_by(User.id.desc()).limit(10).all()
    
    return render_template("admin.html", 
                           total_reports=total_reports, 
                           pending_items=pending_items, 
                           claims=claims, 
                           users_count=users_count,
                           pending_reports=pending_reports,
                           users=all_users)

# ---------------- REPORT LOST ----------------
@app.route("/report-lost", methods=["GET", "POST"])
def report_lost():
    if "user" not in session or session.get("role") != "student":
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form.get("item_name")
        category = request.form.get("category")
        date_lost = request.form.get("date_lost")
        location = request.form.get("location")
        description = request.form.get("description")
        
        image = request.files.get("image")
        filename = None
        if image and image.filename != "":
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            
        new_item = Item(
            name=name, category=category, type="lost",
            date=date_lost, time="", location=location,
            description=description, image_filename=filename,
            reported_by=session.get("user_id")
        )
        db.session.add(new_item)
        db.session.commit()
        return redirect(url_for("items"))

    return render_template("report_lost.html")

# ---------------- REPORT FOUND ----------------
@app.route("/report-found", methods=["GET", "POST"])
def report_found():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form.get("item_name")
        category = request.form.get("category")
        date_found = request.form.get("date_found")
        time_found = request.form.get("time_found")
        location = request.form.get("location")
        description = request.form.get("description")
        
        image = request.files.get("image")
        filename = None
        if image and image.filename != "":
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            
        new_item = Item(
            name=name, category=category, type="found",
            date=date_found, time=time_found, location=location,
            description=description, image_filename=filename,
            reported_by=session.get("user_id")
        )
        db.session.add(new_item)
        db.session.commit()
        return redirect(url_for("items"))

    return render_template("report_found.html")

# ---------------- VIEW ITEMS ----------------
@app.route("/items")
def items():
    all_items = Item.query.order_by(Item.created_at.desc()).all()
    # Or just return items for public regardless if active
    return render_template("items.html", items=all_items)

# ---------------- CLAIM ITEMS ----------------
@app.route("/claim", methods=["GET", "POST"])
def claim():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))

    if request.method == "POST":
        item_id = request.form.get("item_id")
        student_name = request.form.get("student_name")
        roll_no = request.form.get("roll_no")
        student_email = request.form.get("student_email")
        proof = request.form.get("proof")
        return_date = request.form.get("return_date")
        return_time = request.form.get("return_time")
        
        item = Item.query.get(item_id)
        if item:
            item.status = 'returned'
            new_claim = Claim(
                item_id=item_id, student_name=student_name, roll_no=roll_no,
                student_email=student_email, proof_description=proof,
                return_date=return_date, return_time=return_time,
                verified_by=session.get("user_id")
            )
            db.session.add(new_claim)
            db.session.commit()
            return redirect(url_for("items"))
            
    active_found_items = Item.query.filter_by(type='found', status='active').all()
    return render_template("claim.html", items=active_found_items)

# ---------------- NOTIFICATIONS ----------------
@app.route("/notifications")
def notifications():
    if "user" not in session:
        return redirect(url_for("login"))
    # In a real app we would query Notification model
    return render_template("notifications.html")

if __name__ == "__main__":
    app.run(debug=True)