import os
import re
import base64
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from bson.objectid import ObjectId

# ---------------- APP SETUP ----------------
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

app.config["TEMPLATES_AUTO_RELOAD"] = True

app.permanent_session_lifetime = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

UPLOAD_FOLDER = os.path.join(basedir, "upload")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ---------------- MONGODB ----------------
from pymongo import MongoClient
client = MongoClient("mongodb+srv://group_user:CampusFind123@cluster0.lg5y6u3.mongodb.net/?retryWrites=true&w=majority")
db = client["lost_found_db"]

users_collection = db["users"]
items_collection = db["items"]
claims_collection = db["claims"]

# ---------------- HOME ----------------
@app.route("/")
def home():
    items = list(items_collection.find({"status":"active"}).sort("created_at",-1).limit(4))
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
        staff_code = request.form.get("staff_code")

        if password != confirm:
            return render_template("register.html", error="Passwords do not match")

        if not re.match(r"^[a-zA-Z0-9]+@[a-zA-Z0-9]+\.pdpu\.ac\.in$", email.lower()):
            return render_template("register.html", error="Use college email: 24bcp001@sot.pdpu.ac.in")

        if len(password) < 8 or not re.search(r"[a-zA-Z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[@#$%^&+=_!\-]", password):
            return render_template("register.html", error="Password must be 8+ chars with letters, numbers, and a special character (@, #, etc.)")

        if role == "admin":
            if not admin_code or admin_code != "campusadmin@123":
                return render_template("register.html", error="Invalid admin code")

        if role == "staff":
            if not staff_code or staff_code != "campusstaff@123":
                return render_template("register.html", error="Invalid staff code")

        existing = users_collection.find_one({"email": email})
        if existing:
            return render_template("register.html", error="Email already registered")

        hashed = generate_password_hash(password)

        users_collection.insert_one({
            "email": email,
            "role": role,
            "password_hash": hashed
        })

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

        user = users_collection.find_one({"email": email})

        if user and check_password_hash(user["password_hash"], password):

            if user["role"] != role:
                return render_template("login.html", error="Wrong role selected")

            session["user"] = user["email"]
            session["user_id"] = str(user["_id"])
            session["role"] = user["role"]

            session["first_login"] = True

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

    show_welcome = session.pop("first_login", False)
    report_success = session.pop("report_success", False)
    return render_template("student.html", show_welcome=show_welcome, report_success=report_success)

@app.route("/staff")
def staff():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))
    report_success = session.pop("report_success", False)
    return render_template("staff.html", report_success=report_success)

@app.route("/admin")
def admin():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    total_reports = items_collection.count_documents({})
    pending_items = items_collection.count_documents({"status":"active"})
    users_count = users_collection.count_documents({})
    claims = claims_collection.count_documents({})

    pending_reports = list(items_collection.find({"status":"active"}).sort("created_at",-1).limit(10))
    users = list(users_collection.find().sort("_id",-1))

    return render_template(
        "admin.html",
        total_reports=total_reports,
        pending_items=pending_items,
        users_count=users_count,
        claims=claims,
        pending_reports=pending_reports,
        users=users
    )

# ---------------- NOTIFICATIONS ----------------
@app.route("/notification_student")
def notification_student():
    if "user" not in session or session.get("role") != "student":
        return redirect(url_for("login"))
    return render_template("notification_student.html")

@app.route("/notifications")
def notifications():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))
    return render_template("notification_staff.html")

@app.route("/claim", methods=["GET", "POST"])
def claim():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))
    
    if request.method == "POST":
        # Handle claim processing
        item_id = request.form.get("item_id")
        item_name = request.form.get("item_name")
        student_name = request.form.get("student_name")
        roll_no = request.form.get("roll_no")
        student_email = request.form.get("student_email")
        proof = request.form.get("proof")
        return_date = request.form.get("return_date")
        return_time = request.form.get("return_time")
        
        # Update item status to returned
        items_collection.update_one(
            {"_id": ObjectId(item_id)},
            {"$set": {"status": "returned"}}
        )
        
        # Record the claim
        claims_collection.insert_one({
            "item_id": ObjectId(item_id),
            "item_name": item_name,
            "student_name": student_name,
            "roll_no": roll_no,
            "student_email": student_email,
            "proof": proof,
            "return_date": f"{return_date} {return_time}",
            "processed_by": session["user_id"],
            "processed_at": datetime.utcnow()
        })
        
        return redirect(url_for("items"))
    
    # GET request - show claim form
    item_id = request.args.get("item_id")
    if item_id:
        item = items_collection.find_one({"_id": ObjectId(item_id)})
        return render_template("claim.html", selected_item_name=item["name"], selected_item_id=item_id)
    else:
        return render_template("claim.html")

# ---------------- REPORT LOST ITEM ----------------
@app.route("/report-lost", methods=["GET", "POST"])
def report_lost():

    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        name = request.form.get("item_name")
        category = request.form.get("category")
        date = request.form.get("date_lost")
        location = request.form.get("location")
        description = request.form.get("description")

        items_collection.insert_one({
            "name": name,
            "category": category,
            "type": "lost",
            "date": date,
            "location": location,
            "description": description,
            "status": "active",
            "reported_by": session["user_id"],
            "created_at": datetime.utcnow()
        })

        session["report_success"] = True
        return redirect(url_for("student"))

    return render_template("report_lost.html")

# ---------------- REPORT FOUND ITEM ----------------
@app.route("/report-found", methods=["GET","POST"])
def report_found():

    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        name = request.form.get("item_name")
        category = request.form.get("category")
        date = request.form.get("date_found")
        time_found = request.form.get("time_found")
        location = request.form.get("location")
        description = request.form.get("description")

        type_ = "found"

        # combine date + time
        date_combined = f"{date} {time_found}" if time_found else date

        # camera image (if captured)
        filename = request.form.get("uploaded_image")

        # file upload image
        image = request.files.get("image")

        if image and image.filename != "":
            filename = secure_filename(image.filename)

            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

            image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        # MongoDB item document
        item = {
            "name": name,
            "category": category,
            "type": type_,
            "date": date_combined,
            "location": location,
            "description": description,
            "image": filename,
            "status": "active",
            "reported_by": session["user_id"],
            "created_at": datetime.utcnow()
        }

        items_collection.insert_one(item)

        session["report_success"] = True
        return redirect(url_for("staff"))

    uploaded_image = session.get("uploaded_image")

    return render_template("report_found.html", uploaded_image=uploaded_image)
# ---------------- ITEMS ----------------
@app.route("/items")
def items():

    if "user" not in session:
        return redirect(url_for("login"))

    role = session.get("role")

    if role == "staff":
        items = list(items_collection.find().sort("created_at",-1).limit(50))
        return render_template("items_staff.html", items=items)

    else:
        items = list(items_collection.find({"status":{"$ne":"returned"}}).sort("created_at",-1).limit(50))
        return render_template("items_student.html", items=items)

# ---------------- CAMERA ----------------
@app.route("/camera")
def camera():
    return_url = request.args.get("next", url_for("report_found"))
    return render_template("camera.html", return_url=return_url)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ---------------- UPLOAD ----------------
@app.route("/upload", methods=["GET","POST"])
def upload():

    if request.method == "POST":

        image_data = request.form.get("image")

        if not image_data:
            return "No image received"

        image_data = image_data.split(",")[1]
        image_bytes = base64.b64decode(image_data)

        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

        filename = secure_filename(f"camera_{datetime.now().timestamp()}.png")
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        with open(filepath, "wb") as f:
            f.write(image_bytes)

        session["uploaded_image"] = filename

        next_url = request.args.get("next") or url_for("report_found")
        return redirect(next_url)

    return render_template("camera.html", return_url=url_for("report_found"))

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)