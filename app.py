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

# ---------------- CHATBOT API ----------------

# Built-in FAQ knowledge base for CampusFind
CHATBOT_FAQ = {
    "report lost": "To report a lost item:\n1. Log in with your student account\n2. Go to your Student Dashboard\n3. Click 'Report Lost Item'\n4. Fill in the item name, category, date lost, location, and description\n5. Submit the form — your report will be visible to security staff!",
    "report found": "To report a found item (security staff only):\n1. Log in with your staff account\n2. Go to your Security Dashboard\n3. Click 'Report Found Item'\n4. Fill in item details, take a photo (camera or upload), and submit\n5. The item will appear in the system for students to browse.",
    "claim": "To claim a found item:\n1. A security staff member processes claims\n2. The student must provide proof of ownership\n3. Staff verifies the claim and logs the return\n4. The item status changes to 'Returned'.",
    "browse items": "To browse found items:\n1. Log in to your account\n2. Click 'Browse Found Items' from your dashboard\n3. You'll see all active found items with details and images\n4. If you spot your item, contact security staff to initiate a claim.",
    "register": "To register on CampusFind:\n1. Go to the Register page\n2. Enter your PDPU college email (e.g., 24bcp001@sot.pdpu.ac.in)\n3. Select your role (Student, Staff, or Admin)\n4. Create a secure password (8+ chars with letters, numbers, and special characters)\n5. Submit and then log in!",
    "login": "To log in:\n1. Go to the Login page\n2. Enter your registered college email\n3. Select your role (Student / Staff / Admin)\n4. Enter your password\n5. You'll be redirected to your dashboard.",
    "what is campusfind": "CampusFind is the official Lost & Found portal for PDEU (Pandit Deendayal Energy University). It helps students report lost items and security staff log found items, making it easy to reunite people with their belongings.",
    "notifications": "Notifications keep you updated about your reports. You can view them by clicking the bell icon in your dashboard navbar. Use 'Mark all as read' to clear them.",
    "roles": "CampusFind has three roles:\n• **Student** — Report lost items, browse found items\n• **Security Staff** — Report found items, process claims, verify ownership\n• **Admin** — View all reports, manage users, see analytics",
    "contact": "For support, contact CampusFind at support@campusfind.pdeu.ac.in or visit the security office at PDEU Campus, Knowledge Corridor, Gandhinagar.",
    "how does it work": "Here's how CampusFind works:\n1. **Student loses an item** → Reports it on the portal\n2. **Security finds an item** → Logs it with photo and details\n3. **Student browses found items** → Spots their item\n4. **Staff processes the claim** → Verifies ownership and returns the item\nIt's that simple!",
    "hello": "Hello! I'm the CampusFind Assistant. I can help you with:\n• How to report lost/found items\n• How claiming works\n• How to register and log in\n• General questions about CampusFind\nJust ask me anything!",
    "hi": "Hi there! I'm the CampusFind Assistant. Ask me anything about the Lost & Found portal — reporting items, claims, registration, and more!",
    "help": "I can help you with:\n• Reporting lost items\n• Reporting found items (staff)\n• Browsing found items\n• Claiming items\n• Registration & Login\n• Understanding roles\n• How the system works\nJust type your question!"
}

def find_faq_answer(user_message):
    """Check if the user message matches any FAQ keyword as a whole word."""
    msg = user_message.lower().strip()
    
    for keyword, answer in CHATBOT_FAQ.items():
        if re.search(rf"\b{re.escape(keyword)}\b", msg):
            return answer
    return None

def ask_gemini(user_message):
    """Send the question to Gemini AI with CampusFind context."""
    if not GEMINI_AVAILABLE:
        return "AI-powered answers require the google-generativeai package. Please install it with: pip install google-generativeai"

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "I'm sorry, AI-powered answers are currently unavailable. Please try asking about reporting items, claiming, registration, or how CampusFind works!"

    try:
        genai.configure(api_key=api_key)
        
        system_context = (
            "You are the CampusFind Assistant, a helpful chatbot for the PDEU..."
            # ... rest of your instructions ...
        )
        
        # Pass the instructions directly to the model configuration
        model = genai.GenerativeModel(
            "gemini-2.0-flash",
            system_instruction=system_context
        )

        # Now just pass the user's raw message
        response = model.generate_content(user_message)
        return response.text

        system_context = (
            "You are the CampusFind Assistant, a helpful chatbot for the PDEU (Pandit Deendayal Energy University) "
            "Lost & Found portal called CampusFind. The portal allows students to report lost items, security staff "
            "to log found items with photos, and staff to process claims by verifying ownership. "
            "Users register with their PDPU college email. There are three roles: Student, Security Staff, and Admin. "
            "Keep your answers concise, friendly, and helpful. If the question is unrelated to lost-and-found or campus, "
            "still answer politely but briefly. Use emojis sparingly."
        )

        response = model.generate_content(f"{system_context}\n\nUser question: {user_message}")
        return response.text
    except Exception as e:
        return "I'm having trouble connecting to AI services right now. Please try again in a moment, or ask me about CampusFind features like reporting items, claims, or registration!"

@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json()
    if not data or "message" not in data:
        return jsonify({"reply": "Please send a message."}), 400

    user_message = data["message"].strip()
    if not user_message:
        return jsonify({"reply": "Please type a question and I'll help!"}), 400

    # Try FAQ first
    faq_answer = find_faq_answer(user_message)
    if faq_answer:
        return jsonify({"reply": faq_answer, "source": "faq"})

    # Fallback to Gemini AI
    ai_answer = ask_gemini(user_message)
    return jsonify({"reply": ai_answer, "source": "gemini"})

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)