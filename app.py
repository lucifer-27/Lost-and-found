import os
import re
import base64
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, jsonify
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
client = MongoClient("mongodb+srv://vivanpandya15_db_user:Vivan123@cluster0.lg5y6u3.mongodb.net/?appName=Cluster0")
db = client["lost_found_db"]

users_collection = db["users"]
items_collection = db["items"]
archived_items_collection = db["archived_items"]
claims_collection = db["claims"]
notifications_collection = db["notifications"]

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

@app.route("/student-history")
def student_history():
    if "user" not in session or session.get("role") != "student":
        return redirect(url_for("login"))
    return render_template("student_history.html")

@app.route("/staff")
def staff():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))
    report_success = session.pop("report_success", False)
    return render_template("staff.html", report_success=report_success)

@app.route("/pending-claims")
def pending_claims():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))
    return render_template("pending_claims.html")

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

# -------- REQUEST CLAIM (STUDENT) --------
@app.route("/request-claim", methods=["POST"])
def request_claim():
    if "user" not in session or session.get("role") != "student":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        # Get student data
        user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
        student_email = user["email"]
        
        # Extract roll number from email (format: 24bcp001@sot.pdpu.ac.in)
        roll_no = student_email.split("@")[0]
        
        data = request.get_json()
        item_id = data.get("item_id")
        student_name = data.get("student_name")
        description_lost = data.get("description_lost")
        
        # Get item details
        item = items_collection.find_one({"_id": ObjectId(item_id)})
        if not item:
            return jsonify({"error": "Item not found"}), 404
        
        # Record the claim request
        claim_record = {
            "item_id": ObjectId(item_id),
            "item_name": item["name"],
            "item_description": item["description"],
            "item_category": item["category"],
            "item_location": item.get("location", "Not specified"),
            "item_found_date": item.get("date", "Not specified"),
            "student_name": student_name,
            "student_email": student_email,
            "roll_no": roll_no,
            "student_description": description_lost,
            "status": "pending",
            "requested_at": datetime.utcnow(),
            "requested_by": session["user_id"]
        }
        
        result = claims_collection.insert_one(claim_record)
        
        return jsonify({
            "success": True,
            "message": "Claim request submitted successfully! Staff will review your claim.",
            "claim_id": str(result.inserted_id)
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/items/staff", methods=["GET"])
def get_staff_items():
    if "user" not in session or session.get("role") != "staff":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        # Get all active items (not archived)
        items = list(items_collection.find({"status": "active"}).sort("created_at", -1))
        
        # Convert ObjectId to string for JSON serialization
        for item in items:
            item["_id"] = str(item["_id"])
            if "created_at" in item:
                item["created_at"] = item["created_at"].isoformat()
        
        return jsonify({"items": items})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/pending-claims")
def get_pending_claims():
    claims = list(claims_collection.find())
    return jsonify(claims)
    
    try:
        pending = list(claims_collection.find({"status": "pending"}).sort("created_at", -1))
        
        # Convert ObjectId to string for JSON serialization
        for claim in pending:
            claim["_id"] = str(claim["_id"])
            claim["item_id"] = str(claim["item_id"])
            claim["created_at"] = claim["created_at"].isoformat()
        
        return jsonify(pending)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/claim/<claim_id>/status", methods=["POST"])
def update_claim_status(claim_id):
    if "user" not in session or session.get("role") != "staff":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        data = request.get_json()
        new_status = data.get("status")  # "approved", "rejected", "returned"
        
        if new_status not in ["approved", "rejected", "returned"]:
            return jsonify({"error": "Invalid status"}), 400
        
        # Update claim status
        claims_collection.update_one(
            {"_id": ObjectId(claim_id)},
            {"$set": {"status": new_status, "processed_by": session["user_id"], "processed_at": datetime.utcnow()}}
        )
        
        # If approved, create notification for student
        if new_status == "returned":
            claim = claims_collection.find_one({"_id": ObjectId(claim_id)})
            student_id = claim.get("requested_by")
            
            # Create notification for student
            notifications_collection.insert_one({
                "user_id": ObjectId(student_id),
                "type": "returned",
                "title": f"Your Item '{claim['item_name']}' Has Been Returned!",
                "message": f"The item '{claim['item_name']}' that you claimed has been processed and is ready for pickup.",
                "item_name": claim["item_name"],
                "roll_no": claim["roll_no"],
                "created_at": datetime.utcnow(),
                "read": False
            })
        
        return jsonify({"success": True, "message": "Claim status updated"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/notifications/student", methods=["GET"])
def get_student_notifications():
    if "user" not in session or session.get("role") != "student":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        user_id = ObjectId(session["user_id"])
        notifications = list(notifications_collection.find({"user_id": user_id}).sort("created_at", -1).limit(50))
        
        for notif in notifications:
            notif["_id"] = str(notif["_id"])
            notif["user_id"] = str(notif["user_id"])
            notif["created_at"] = notif["created_at"].isoformat()
        
        return jsonify(notifications)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/notifications/<notification_id>/read", methods=["POST"])
def mark_notification_read(notification_id):
    if "user" not in session or session.get("role") != "student":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        notifications_collection.update_one(
            {"_id": ObjectId(notification_id)},
            {"$set": {"read": True}}
        )
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/notifications/<notification_id>/dismiss", methods=["POST"])
def dismiss_notification(notification_id):
    if "user" not in session or session.get("role") != "student":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        notifications_collection.delete_one(
            {"_id": ObjectId(notification_id)}
        )
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/notifications/staff", methods=["GET"])
def get_staff_notifications():
    if "user" not in session or session.get("role") != "staff":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        user_id = ObjectId(session["user_id"])
        notifications = list(notifications_collection.find({"staff_id": user_id}).sort("created_at", -1).limit(50))
        
        for notif in notifications:
            notif["_id"] = str(notif["_id"])
            notif["staff_id"] = str(notif["staff_id"])
            notif["created_at"] = notif["created_at"].isoformat()
        
        return jsonify(notifications)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/notifications/staff/<notification_id>/read", methods=["POST"])
def mark_staff_notification_read(notification_id):
    if "user" not in session or session.get("role") != "staff":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        notifications_collection.update_one(
            {"_id": ObjectId(notification_id)},
            {"$set": {"read": True}}
        )
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/notifications/staff/<notification_id>/dismiss", methods=["POST"])
def dismiss_staff_notification(notification_id):
    if "user" not in session or session.get("role") != "staff":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        notifications_collection.delete_one(
            {"_id": ObjectId(notification_id)}
        )
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/archived-items", methods=["GET"])
def get_archived_items():
    if "user" not in session or session.get("role") != "staff":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        archived = list(archived_items_collection.find().sort("archived_at", -1).limit(100))
        
        # Convert ObjectId to string for JSON serialization
        for item in archived:
            item["_id"] = str(item["_id"])
            item["original_id"] = str(item["original_id"])
            item["claim_id"] = str(item["claim_id"])
            if "archived_at" in item:
                item["archived_at"] = item["archived_at"].isoformat()
        
        return jsonify(archived)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/archived-items/<item_id>", methods=["GET"])
def get_archived_item_details(item_id):
    if "user" not in session or session.get("role") != "staff":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        item = archived_items_collection.find_one({"_id": ObjectId(item_id)})
        if not item:
            return jsonify({"error": "Item not found"}), 404
        
        # Get associated claim details
        claim = claims_collection.find_one({"_id": item.get("claim_id")})
        
        item["_id"] = str(item["_id"])
        item["original_id"] = str(item["original_id"])
        item["claim_id"] = str(item["claim_id"])
        
        return jsonify({"item": item, "claim": claim})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/archived-items/<item_id>/edit", methods=["POST"])
def edit_archived_item(item_id):
    if "user" not in session or session.get("role") != "staff":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        data = request.get_json()
        
        archived_items_collection.update_one(
            {"_id": ObjectId(item_id)},
            {"$set": {
                "name": data.get("name"),
                "description": data.get("description"),
                "category": data.get("category"),
                "location": data.get("location"),
                "last_edited_by_staff": session["user_id"],
                "last_edited_at": datetime.utcnow()
            }}
        )
        
        return jsonify({"success": True, "message": "Item details updated"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/student/<student_id>/flag", methods=["POST"])
def flag_student(student_id):
    if "user" not in session or session.get("role") != "staff":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        data = request.get_json()
        reason = data.get("reason", "Multiple false claims or suspicious activity")
        
        # Update student account
        users_collection.update_one(
            {"_id": ObjectId(student_id)},
            {"$set": {
                "account_flagged": True,
                "flag_reason": reason,
                "flagged_at": datetime.utcnow(),
                "flagged_by_staff": session["user_id"]
            }}
        )
        
        # Create notification for student
        notifications_collection.insert_one({
            "user_id": ObjectId(student_id),
            "type": "account_flagged",
            "title": "Account Warning",
            "message": f"Your account has been flagged by staff. Reason: {reason}. Multiple violations may result in account suspension.",
            "created_at": datetime.utcnow(),
            "read": False
        })
        
        return jsonify({"success": True, "message": "Student flagged successfully"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/student-history", methods=["GET"])
def student_history_api():
    if "user" not in session or session.get("role") != "student":
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        student_id = ObjectId(session["user_id"])
        
        # Get student info to check if flagged
        student = users_collection.find_one({"_id": student_id})
        
        # Get all archived items claimed by this student
        archived_items = list(archived_items_collection.find(
            {"claimed_by": student_id}
        ).sort("archived_at", -1))
        
        # Convert ObjectId to string for JSON serialization
        for item in archived_items:
            item["_id"] = str(item["_id"])
            if "claimed_by" in item:
                item["claimed_by"] = str(item["claimed_by"])
        
        return jsonify({
            "items": archived_items,
            "student": {
                "name": student.get("name", ""),
                "account_flagged": student.get("account_flagged", False),
                "flag_reason": student.get("flag_reason", "")
            }
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
        # Students can only see FOUND items
        items = list(items_collection.find({"type": "found", "status":"active"}).sort("created_at",-1).limit(50))
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