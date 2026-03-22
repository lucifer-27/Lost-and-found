# CampusFind Backend Application (Flask + MongoDB)
# This application manages lost and found items in a campus environment,
# Including user roles (student, staff, admin), item tracking, claim handling, and notifications.

import os
import re
import sys
import base64
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, Response
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from bson.objectid import ObjectId
from bson.binary import Binary
from gridfs import GridFS
# ---------------- APP SETUP ----------------
basedir = os.path.abspath(os.path.dirname(__file__))


def load_local_env(env_path):
    if not os.path.exists(env_path):
        return

    with open(env_path, "r", encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if key and key not in os.environ:
                os.environ[key] = value


load_local_env(os.path.join(basedir, ".env"))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

app.config["TEMPLATES_AUTO_RELOAD"] = True

app.permanent_session_lifetime = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ---------------- MONGODB ----------------
# Use environment-provided Mongo settings only. Hardcoding Atlas credentials
# makes local failures harder to debug and is unsafe to keep in source.
MONGO_URI = os.environ.get("MONGO_URI", "").strip()
MONGO_DIRECT_URI = os.environ.get("MONGO_DIRECT_URI", "").strip()
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "lost_found_db")


def _redact_mongo_uri(uri):
    return re.sub(r"(mongodb(?:\+srv)?://[^:]+:)[^@]+@", r"\1***@", uri)


def _connect_mongo(uri):
    client = MongoClient(
        uri,
        serverSelectionTimeoutMS=10000,
        connectTimeoutMS=10000,
        socketTimeoutMS=10000,
    )
    client.admin.command("ping")
    return client


def create_mongo_client():
    tried = []

    connection_options = []
    if MONGO_DIRECT_URI:
        connection_options.append(("MONGO_DIRECT_URI", MONGO_DIRECT_URI))
    if MONGO_URI:
        connection_options.append(("MONGO_URI", MONGO_URI))

    if not connection_options:
        print("\nERROR: MongoDB is not configured.")
        print("Set either MONGO_DIRECT_URI or MONGO_URI in your environment or .env file, then restart the app.")
        print("Tip: if your network blocks SRV DNS lookups, prefer MONGO_DIRECT_URI with explicit Atlas hosts.")
        sys.exit(1)

    for label, uri in connection_options:
        if not uri or uri in tried:
            continue
        tried.append(uri)
        try:
            return _connect_mongo(uri)
        except Exception as exc:
            if label == "MONGO_DIRECT_URI" and MONGO_URI:
                print(f"WARNING: {label} failed, trying MONGO_URI fallback.")
            elif label == "MONGO_URI" and uri.startswith("mongodb+srv://") and MONGO_DIRECT_URI:
                print(f"WARNING: {label} failed, trying MONGO_DIRECT_URI fallback.")
            else:
                print(f"WARNING: {label} failed.")
            print(f"URI: {_redact_mongo_uri(uri)}")
            print("Reason:", repr(exc))

    print("\nERROR: Failed to connect to MongoDB.")
    print("Tried these URIs:")
    for uri in tried:
        print(" -", _redact_mongo_uri(uri))
    print("\nCommon causes: network/DNS blocking SRV lookups, incorrect URI, or missing dnspython package.")
    print("Suggested fixes:")
    print(" - If SRV DNS is blocked, set MONGO_DIRECT_URI to the standard 'mongodb://' Atlas connection string with explicit hosts")
    print(" - Set MONGO_URI or MONGO_DIRECT_URI in your environment, then restart the app")
    print(" - Ensure your machine can resolve the Atlas host: nslookup cluster0.lg5y6u3.mongodb.net")
    print(" - Ensure 'dnspython' is installed: pip install dnspython")
    sys.exit(1)


client = create_mongo_client()
db = client[MONGO_DB_NAME]

fs = GridFS(db)

users_collection = db["users"]
items_collection = db["items"]
archived_items_collection = db["archived_items"]
claims_collection = db["claims"]
notifications_collection = db["notifications"]   
temp_uploads_collection = db["temp_uploads"]
temp_uploads_collection.create_index("created_at", expireAfterSeconds=3600)

# ---------------- CATEGORIES ----------------
categories = [
    "Electronics",
    "Clothing",
    "Wallets & Purses",
    "ID Cards & Documents",
    "Keys",
    "Books & Stationery",
    "Bags & Backpacks",
    "Accessories",
    "Water Bottles & Containers",
    "Other",
]

DEFAULT_IMAGE_CONTENT_TYPE = "image/jpeg"
ITEM_LIST_PROJECTION = {
    "image": 0,
    "image_content_type": 0,
    "image_filename": 0,
}


def _normalize_image_content_type(content_type):
    if content_type and content_type.startswith("image/"):
        return content_type
    return DEFAULT_IMAGE_CONTENT_TYPE


def _build_item_image_fields(image_bytes=None, content_type=None, filename=None):
    if not image_bytes:
        return {
            "image": None,
            "image_content_type": None,
            "image_filename": None,
        }

    return {
        "image": Binary(image_bytes),
        "image_content_type": _normalize_image_content_type(content_type),
        "image_filename": filename or None,
    }


def _build_data_image_src(image_bytes, content_type):
    if not image_bytes:
        return None

    encoded = base64.b64encode(image_bytes).decode("ascii")
    return f"data:{_normalize_image_content_type(content_type)};base64,{encoded}"


def _extract_item_image_src(item):
    image_value = item.get("image")
    content_type = item.get("image_content_type") or DEFAULT_IMAGE_CONTENT_TYPE

    if isinstance(image_value, (bytes, bytearray, Binary)):
        return _build_data_image_src(bytes(image_value), content_type)

    if isinstance(image_value, str):
        if image_value.startswith("data:image"):
            return image_value
        return f"data:{content_type};base64,{image_value}"

    legacy_image_id = item.get("image_id")
    if legacy_image_id:
        try:
            legacy_file = fs.get(legacy_image_id if isinstance(legacy_image_id, ObjectId) else ObjectId(legacy_image_id))
            return _build_data_image_src(legacy_file.read(), getattr(legacy_file, "content_type", None))
        except Exception:
            return None

    return None


def _store_temp_upload(image_bytes, content_type, filename=None):
    upload = {
        "image": Binary(image_bytes),
        "image_content_type": _normalize_image_content_type(content_type),
        "image_filename": filename or None,
        "created_at": datetime.utcnow(),
    }
    return str(temp_uploads_collection.insert_one(upload).inserted_id)


def _get_temp_upload(upload_id):
    if not upload_id:
        return None

    try:
        return temp_uploads_collection.find_one({"_id": ObjectId(upload_id)})
    except Exception:
        return None


def _delete_temp_upload(upload_id):
    if not upload_id:
        return

    try:
        temp_uploads_collection.delete_one({"_id": ObjectId(upload_id)})
    except Exception:
        pass


def _clear_uploaded_image_session():
    upload_id = session.pop("uploaded_image_id", None)
    if upload_id:
        _delete_temp_upload(upload_id)


def _consume_temp_upload(upload_id):
    upload = _get_temp_upload(upload_id)
    if not upload:
        return None, None, None

    _delete_temp_upload(upload_id)
    return (
        bytes(upload.get("image") or b""),
        upload.get("image_content_type"),
        upload.get("image_filename"),
    )


def _build_claim_status_badge(status):
    normalized = (status or "").lower()
    if normalized == "returned":
        return {
            "label": "Returned",
            "classes": "bg-green-100 text-green-700",
        }
    if normalized == "approved":
        return {
            "label": "Approved",
            "classes": "bg-blue-100 text-blue-700",
        }
    if normalized == "rejected":
        return {
            "label": "Rejected",
            "classes": "bg-red-100 text-red-700",
        }
    if normalized == "pending":
        return {
            "label": "Pending",
            "classes": "bg-amber-100 text-amber-700",
        }
    return {
        "label": "No Claims",
        "classes": "bg-gray-100 text-gray-700",
    }


def _build_item_timeline(item, claims):
    reported_label = "Reported Found" if item.get("type") == "found" else "Reported Lost"
    steps = [
        {"name": reported_label, "completed": True, "date": item.get("created_at")},
        {"name": "Claim Requested", "completed": False, "date": None},
        {"name": "Claim Approved", "completed": False, "date": None},
        {"name": "Ready for Pickup", "completed": False, "date": None},
        {"name": "Item Returned", "completed": False, "date": None},
    ]

    if claims:
        ordered_claims = sorted(
            claims,
            key=lambda claim: claim.get("requested_at") or datetime.min,
        )
        steps[1]["completed"] = True
        steps[1]["date"] = ordered_claims[0].get("requested_at")

        final_claim = next(
            (claim for claim in claims if claim.get("status") in ["approved", "returned"]),
            None,
        )
        if final_claim:
            processed_at = final_claim.get("processed_at")
            steps[2]["completed"] = True
            steps[2]["date"] = processed_at
            steps[3]["completed"] = True
            steps[3]["date"] = processed_at

            if item.get("status") == "returned":
                steps[4]["completed"] = True
                steps[4]["date"] = processed_at

    return steps


def _enrich_claim_records(claims):
    for claim in claims:
        try:
            student = users_collection.find_one({"_id": ObjectId(claim["requested_by"])}) if claim.get("requested_by") else None
            claim["student_email"] = student["email"] if student else claim.get("student_email", "Unknown")
        except Exception:
            claim["student_email"] = claim.get("student_email", "Unknown")

        claim["claim_badge"] = _build_claim_status_badge(claim.get("status"))

        if claim.get("processed_by"):
            try:
                staff = users_collection.find_one({"_id": ObjectId(claim["processed_by"])})
                claim["staff_email"] = staff["email"] if staff else "Unknown Staff"
            except Exception:
                claim["staff_email"] = "Unknown Staff"
    return claims


def _find_item_for_detail(item_id):
    try:
        item_object_id = ObjectId(item_id)
    except Exception:
        return None, None

    item = items_collection.find_one({"_id": item_object_id})
    if item:
        return item, item["_id"]

    archived_item = archived_items_collection.find_one({"_id": item_object_id})
    if archived_item:
        return archived_item, archived_item.get("original_item_id") or archived_item["_id"]

    archived_item = archived_items_collection.find_one({"original_item_id": item_object_id})
    if archived_item:
        return archived_item, archived_item.get("original_item_id") or archived_item["_id"]

    return None, None


def _prepare_item_detail_context(item_id, role, user_id=None):
    item, claim_item_id = _find_item_for_detail(item_id)
    if not item:
        return None

    reporter_fields = get_user_display_fields(find_user_by_id(item.get("reported_by")))
    item["reporter_name"] = reporter_fields["name"]
    item["reporter_roll_no"] = reporter_fields["roll_no"]
    item["reporter_email"] = reporter_fields["email"]
    item["image_src"] = _extract_item_image_src(item)

    claims = []
    if claim_item_id:
        claims = list(claims_collection.find({"item_id": claim_item_id}).sort("requested_at", -1))
        claims = _enrich_claim_records(claims)

    user_claim = None
    if role == "student" and user_id and claim_item_id:
        user_claim = next((claim for claim in claims if str(claim.get("requested_by", "")) == str(user_id)), None)

    claim_status_source = user_claim or (claims[0] if claims else None)
    claim_status = _build_claim_status_badge(claim_status_source.get("status") if claim_status_source else None)

    item["claim_status_label"] = claim_status["label"]
    item["claim_status_classes"] = claim_status["classes"]
    item["date_label"] = "Found Date" if item.get("type") == "found" else "Lost Date"

    return {
        "item": item,
        "claims": claims,
        "user_claim": user_claim,
        "steps": _build_item_timeline(item, claims),
    }

# ---------------- NOTIFICATION FUNCTION ----------------
def create_notification(user_id, role, message, notif_type="general"):

    notifications_collection.insert_one({
        "user_id": str(user_id),   # ALWAYS string
        "role": role,
        "message": message,
        "type": notif_type,
        "read": False,
        "created_at": datetime.utcnow()
    })


def get_user_display_fields(user_doc):
    if not user_doc:
        return {
            "name": "Unknown User",
            "roll_no": "--",
            "email": "",
        }

    email = user_doc.get("email", "")
    return {
        "name": user_doc.get("name") or user_doc.get("full_name") or "Unknown User",
        "roll_no": email.split("@")[0] if "@" in email else (email or "--"),
        "email": email,
    }


def find_user_by_id(user_id):
    if not user_id:
        return None

    try:
        return users_collection.find_one({"_id": ObjectId(str(user_id))})
    except:
        return users_collection.find_one({"_id": user_id})

# ---------------- HOME ----------------
@app.route("/")
def home():
    items = list(items_collection.find({"status":"active"}, ITEM_LIST_PROJECTION).sort("created_at",-1).limit(4))
    return render_template("index.html", recent_items=items)

# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():

    if "user" in session:
        return redirect(url_for("home"))

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
            "name": full_name,
            "full_name": full_name,
            "email": email,
            "role": role,
            "password_hash": hashed,
            "account_flagged": False
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
 
@app.route("/pending-claims")
def pending_claims():

    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))

    claims = list(
        claims_collection.find({"status": "pending"}).sort("requested_at", -1)
    )

    claims = list(claims_collection.find({"status": "pending"}))
    return render_template("pending_claims.html", claims=claims)

@app.route("/admin")
def admin():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    flag_success = session.pop("flag_success", None)
    report_success = session.pop("report_success", None)

    # 1. System Activity Monitoring Stats
    total_active_items = items_collection.count_documents({"status":"active"})
    total_items = items_collection.count_documents({})
    total_archived = archived_items_collection.count_documents({})
    total_reports = total_items + total_archived

    total_claims_submitted = claims_collection.count_documents({})
    pending_claims = claims_collection.count_documents({"status": "pending"})
    returned_items = claims_collection.count_documents({"status": "returned"})

    now = datetime.utcnow()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    year_start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)

    monthly_reports = items_collection.count_documents({"created_at": {"$gte": month_start}}) + archived_items_collection.count_documents({"created_at": {"$gte": month_start}})
    yearly_reports = items_collection.count_documents({"created_at": {"$gte": year_start}}) + archived_items_collection.count_documents({"created_at": {"$gte": year_start}})

    users_count = users_collection.count_documents({})

    # 2. User Information Management (Enrich arrays)
    users = list(users_collection.find({"account_flagged": {"$ne": True}}).sort("_id",-1))
    
    all_users_items = list(items_collection.find({}, {"reported_by": 1})) + list(archived_items_collection.find({}, {"reported_by": 1}))
    all_claims = list(claims_collection.find({}))
    
    items_by_user = {}
    for item in all_users_items:
        uid = str(item.get("reported_by", ""))
        if uid:
            items_by_user[uid] = items_by_user.get(uid, 0) + 1
            
    claims_dict = {}
    approved_dict = {}
    rejected_dict = {}
    for clm in all_claims:
        uid = str(clm.get("requested_by", ""))
        if uid:
            claims_dict[uid] = claims_dict.get(uid, 0) + 1
            if clm.get("status") in ["returned", "approved"]:
                approved_dict[uid] = approved_dict.get(uid, 0) + 1
            elif clm.get("status") == "rejected":
                rejected_dict[uid] = rejected_dict.get(uid, 0) + 1

    for u in users:
        u_id = str(u["_id"])
        u["total_reports"] = items_by_user.get(u_id, 0)
        u["total_claims"] = claims_dict.get(u_id, 0)
        u["approved_claims"] = approved_dict.get(u_id, 0)
        u["rejected_claims"] = rejected_dict.get(u_id, 0)

    # 3. Claim Monitoring History Table
    all_claim_history = list(claims_collection.find().sort("requested_at", -1).limit(100))
    for claim in all_claim_history:
        clm_user = users_collection.find_one({"_id": ObjectId(claim["requested_by"])}) if claim.get("requested_by") else None
        claim["student_email"] = clm_user["email"] if clm_user else "Unknown"
        
        item = items_collection.find_one({"_id": ObjectId(claim["item_id"])}) or archived_items_collection.find_one({"_id": ObjectId(claim["item_id"])})
        claim["item_name"] = item["name"] if item else "Unknown Item"

    # Pending Reports (Items with/without claims)
    pending_reports = list(items_collection.find({"status":"active"}, ITEM_LIST_PROJECTION).sort("created_at",-1).limit(10))
    for report in pending_reports:
        has_claim = claims_collection.find_one(
            {"item_id": report["_id"], "status": "pending"},
            sort=[("requested_at", -1)]
        )
        if has_claim:
            report["has_claim"] = True
            report["claim_id"] = has_claim["_id"]

            claimant_fields = get_user_display_fields(find_user_by_id(has_claim.get("requested_by")))
            report["student_display_name"] = (
                has_claim.get("student_name")
                or has_claim.get("claimed_by_name")
                or claimant_fields["name"]
                or "Unknown User"
            )
            report["student_roll_no"] = (
                has_claim.get("roll_no")
                or has_claim.get("claimed_by_roll_no")
                or claimant_fields["roll_no"]
                or "--"
            )
        else:
            report["has_claim"] = False

            reporter_fields = get_user_display_fields(find_user_by_id(report.get("reported_by")))
            report["student_display_name"] = reporter_fields["name"]
            report["student_roll_no"] = reporter_fields["roll_no"]

    return render_template(
        "admin.html",
        total_reports=total_reports,
        total_active_items=total_active_items,
        total_claims_submitted=total_claims_submitted,
        pending_claims=pending_claims,
        returned_items=returned_items,
        monthly_reports=monthly_reports,
        yearly_reports=yearly_reports,
        users_count=users_count,
        claims=returned_items,
        pending_reports=pending_reports,
        users=users,
        all_claim_history=all_claim_history,
        flag_success=flag_success,
        report_success=report_success
    )

@app.route("/admin/user/<user_id>")
def admin_user_details(user_id):
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    
    try:
        inspected_user = users_collection.find_one({"_id": ObjectId(user_id)})
    except:
        inspected_user = None
    
    if not inspected_user:
        flash("User not found.", "error")
        return redirect(url_for("admin"))
        
    user_items = list(items_collection.find({"reported_by": user_id}, ITEM_LIST_PROJECTION)) + list(archived_items_collection.find({"reported_by": user_id}, ITEM_LIST_PROJECTION))
    user_items.sort(key=lambda x: x.get("created_at") or datetime.min, reverse=True)
    
    user_claims = list(claims_collection.find({"requested_by": user_id}).sort("requested_at", -1))
    for claim in user_claims:
        try:
            item = items_collection.find_one({"_id": ObjectId(claim["item_id"])}) or archived_items_collection.find_one({"_id": ObjectId(claim["item_id"])})
            claim["item_name"] = item["name"] if item else "Unknown Item"
        except:
            claim["item_name"] = "Unknown Item"
        
        # Fetch staff email if processed
        if claim.get("processed_by"):
            try:
                staff = users_collection.find_one({"_id": ObjectId(claim["processed_by"])})
                claim["staff_email"] = staff["email"] if staff else "Unknown Staff"
            except:
                claim["staff_email"] = "Unknown Staff"

    return render_template(
        "admin_user_details.html",
        inspected_user=inspected_user,
        user_items=user_items,
        user_claims=user_claims,
        flag_success=session.pop("flag_success", None)
    )

@app.route("/admin/item/<item_id>")
def admin_item_status(item_id):
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    context = _prepare_item_detail_context(item_id, "admin", session.get("user_id"))
    if not context:
        flash("Item not found.", "error")
        return redirect(url_for("admin"))

    return render_template(
        "item_details.html",
        item=context["item"],
        claims=context["claims"],
        user_claim=context["user_claim"],
        steps=context["steps"],
        view_mode="admin",
        role="admin",
        back_url=url_for("admin"),
        back_label="Admin Dashboard",
    )

@app.route("/admin/flagged-users")
def flagged_users():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    users = list(users_collection.find({"account_flagged": True}).sort("_id",-1))
    return render_template("flagged_users.html", users=users)

@app.route("/admin/toggle-flag/<user_id>", methods=["POST"])
def toggle_flag(user_id):
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if user:
        # Prevent flagging admin users
        if user.get("role") == "admin":
            session["flag_success"] = "Admin accounts cannot be flagged."
            return redirect(request.referrer or url_for("admin"))
        
        is_flagged = user.get("account_flagged", False)
        new_status = not is_flagged
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"account_flagged": new_status}}
        )
        
        roll_no = user.get("email", "").split("@")[0] if "@" in user.get("email", "") else "User"
        
        if new_status:
            session["flag_success"] = f"Roll no {roll_no} flagged successfully."
        else:
            session["flag_success"] = f"Roll no {roll_no} unflagged successfully."

        # Notify the user
        status_text = "flagged" if new_status else "unflagged"
        create_notification(
            str(user["_id"]),
            "student" if user.get("role") == "student" else "staff",
            f"Your account has been {status_text} by the administrator.",
            "account_flagged" if new_status else "account_unflagged"
        )
        
    return redirect(request.referrer or url_for("admin"))

# ---------------- NOTIFICATIONS ----------------
#Student notifications
@app.route("/notification_student")
def notification_student():

    if "user" not in session or session.get("role") != "student":
        return redirect(url_for("login"))

    user_id = str(session["user_id"])

    notifications = list(
        notifications_collection.find({"user_id": user_id})
        .sort("created_at", -1)
    )

    return render_template("notification_student.html", notifications=notifications)
#Staff notifications
@app.route("/notifications")
def notifications():

    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))

    user_id = str(session["user_id"])

    notifications = list(
        notifications_collection.find({"user_id": user_id})
        .sort("created_at", -1)
    )

    return render_template("notification_staff.html", notifications=notifications)

# Admin notifications
@app.route("/notifications-admin")
def notifications_admin():

    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    user_id = str(session["user_id"])

    notifications = list(
        notifications_collection.find({"user_id": user_id})
        .sort("created_at", -1)
    )

    return render_template("notification_staff.html", notifications=notifications)

# -------- PROCESS CLAIM (STAFF) --------
@app.route("/process-claim/<claim_id>", methods=["GET", "POST"])
def process_claim(claim_id):
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))

    claim = claims_collection.find_one({"_id": ObjectId(claim_id)})
    if not claim:
        return redirect(url_for("pending_claims"))

    if request.method == "GET":
        return render_template("claim.html", claim=claim)

    if request.method == "POST":
        proof = request.form.get("proof")
        return_date = request.form.get("return_date")
        return_time = request.form.get("return_time")

        # Update claim status
        claims_collection.update_one(
            {"_id": ObjectId(claim_id)},
            {"$set": {
                "status": "returned",
                "processed_by": session["user_id"],
                "processed_at": datetime.utcnow(),
                "proof": proof,
                "return_date": f"{return_date} {return_time}"
            }}
        )

        # Update item status to returned
        items_collection.update_one(
            {"_id": claim["item_id"]},
            {"$set": {"status": "returned"}}
        )

        # Get the full item to archive it
        item = items_collection.find_one({"_id": claim["item_id"]})

        # Archive the item
        if item:
            archived_items_collection.insert_one({
                "original_item_id": item["_id"],
                "name": item.get("name", ""),
                "category": item.get("category", ""),
                "type": item.get("type", ""),
                "date": item.get("date", ""),
                "location": item.get("location", ""),
                "description": item.get("description", ""),
                "image": item.get("image"),
                "image_content_type": item.get("image_content_type"),
                "image_filename": item.get("image_filename"),
                "image_id": item.get("image_id"),
                "reported_by": item.get("reported_by", ""),
                "claimed_by_name": claim.get("student_name", ""),
                "claimed_by_email": claim.get("student_email", ""),
                "claimed_by_roll_no": claim.get("roll_no", ""),
                "reason": "returned",
                "proof": proof,
                "return_date_time": f"{return_date} {return_time}",
                "archived_at": datetime.utcnow()
            })

        # Notify the student who requested the claim
        student_user = users_collection.find_one({"email": claim.get("student_email", "")})
        if student_user:
            create_notification(
                str(student_user["_id"]),
                "student",
                f"Your item '{claim.get('item_name', '')}' has been returned successfully! Please collect it from the security office.",
                "returned"
            )

        # Notify staff who processed
        create_notification(
            session["user_id"],
            "staff",
            f"You approved and returned '{claim.get('item_name', '')}' to {claim.get('student_name', '')} ({claim.get('roll_no', '')}).",
            "claim_done"
        )

        return redirect(url_for("pending_claims"))

# -------- MANUAL CLAIM (STAFF, NO STUDENT REQUEST) --------
@app.route("/claim", methods=["GET", "POST"])
def claim():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))

    if request.method == "GET":
        item_id = request.args.get("item_id")
        if item_id:
            item = items_collection.find_one({"_id": ObjectId(item_id)})
            if item:
                return render_template("claim.html", 
                                       selected_item_id=str(item["_id"]),
                                       selected_item_name=item.get("name", ""))
        return render_template("claim.html")

    if request.method == "POST":
        item_id = request.form.get("item_id")
        student_name = request.form.get("student_name")
        roll_no = request.form.get("roll_no")
        student_email = request.form.get("student_email")
        student_user = users_collection.find_one({"email": student_email})

        if not student_user:
            return "Student not found"
        
        student_user_id = str(student_user["_id"])
        proof = request.form.get("proof")
        return_date = request.form.get("return_date")
        return_time = request.form.get("return_time")


        if item_id:
            items_collection.update_one(
                {"_id": ObjectId(item_id)},
                {"$set": {"status": "returned"}}
            )
            item = items_collection.find_one({"_id": ObjectId(item_id)})
            
            if item:
                archived_items_collection.insert_one({
                    "original_item_id": item["_id"],
                    "name": item.get("name", ""),
                    "category": item.get("category", ""),
                    "type": item.get("type", ""),
                    "date": item.get("date", ""),
                    "location": item.get("location", ""),
                    "description": item.get("description", ""),
                    "image": item.get("image"),
                    "image_content_type": item.get("image_content_type"),
                    "image_filename": item.get("image_filename"),
                    "image_id": item.get("image_id"),
                    "reported_by": item.get("reported_by", ""),
                    "claimed_by_name": student_name,
                    "claimed_by_email": student_email,
                    "claimed_by_roll_no": roll_no,
                    "reason": "returned",
                    "proof": proof,
                    "return_date_time": f"{return_date} {return_time}",
                    "archived_at": datetime.utcnow()
                })

                student_user = users_collection.find_one({"email": student_email})
                if student_user:
                    create_notification(
                        str(student_user["_id"]),
                        "student",
                        f"Your item '{item.get('name', '')}' has been returned successfully! Please collect it from the security office.",
                        "returned"
                    )

        create_notification(
            session["user_id"],
            "staff",
            f"You manually returned an item to {student_name} ({roll_no}).",
            "claim_done"
        )

        return redirect(url_for("staff"))

        
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
        # ------------------------------------------------

# -------- REJECT CLAIM (STAFF) --------
@app.route("/reject-claim/<claim_id>", methods=["POST"])
def reject_claim(claim_id):
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))

    claim = claims_collection.find_one({"_id": ObjectId(claim_id)})
    if not claim:
        return redirect(url_for("pending_claims"))

    reason = request.form.get("reason", "")
    is_false_claim = request.form.get("false_claim") == "on"

    # Update claim status
    update_data = {
        "status": "rejected",
        "processed_by": session["user_id"],
        "processed_at": datetime.utcnow(),
        "rejection_reason": reason
    }
    claims_collection.update_one(
        {"_id": ObjectId(claim_id)},
        {"$set": update_data}
    )

    # If false claim, flag the student
    if is_false_claim and reason:
        users_collection.update_one(
            {"email": claim.get("student_email", "")},
            {"$set": {
                "account_flagged": True,
                "flag_reason": reason
            }}
        )

    # Notify the student
    student_user = users_collection.find_one({"email": claim.get("student_email", "")})
    if student_user:
        msg = f"Your claim for '{claim.get('item_name', '')}' has been rejected."
        if reason:
            msg += f" Reason: {reason}"

        notif_type = "account_flagged" if is_false_claim else "claim_rejected"
        create_notification(
            str(student_user["_id"]),
            "student",
            msg,
            notif_type
        )

    return redirect(url_for("pending_claims"))

# -------- REQUEST CLAIM (STUDENT) --------
@app.route("/request-claim", methods=["POST"])
def request_claim():

    if "user" not in session or session.get("role") != "student":
        return redirect(url_for("login"))

    item_id = (request.form.get("item_id") or "").strip()
    student_name = (request.form.get("student_name") or "").strip()
    description_lost = (request.form.get("description_lost") or "").strip()

    if not item_id:
        return redirect(url_for("items"))

    if not student_name or not description_lost:
        session["claim_error"] = "Please fill in your name and item description before submitting."
        return redirect(url_for("items"))

    try:
        item_object_id = ObjectId(item_id)
    except:
        session["claim_error"] = "Invalid item selected."
        return redirect(url_for("items"))

    # Get student email
    user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
    if not user:
        session["claim_error"] = "Your account could not be verified. Please log in again."
        return redirect(url_for("login"))

    student_email = user["email"]

    # Extract roll number
    roll_no = student_email.split("@")[0]

    # Get item info
    item = items_collection.find_one({"_id": item_object_id})

    if not item:
        session["claim_error"] = "This item is no longer available for claim."
        return redirect(url_for("items"))

    # Prevent duplicate pending claim by the same user for the same item.
    existing = claims_collection.find_one({
        "item_id": item_object_id,
        "requested_by": session["user_id"],
        "status": "pending"
    })

    if existing:
        session["claim_error"] = "You already submitted a claim for this item."
        return redirect(url_for("items"))

    # Collect previous pending claimants for staff context, excluding the current user.
    previous_claims = list(
        claims_collection.find(
            {
                "item_id": item_object_id,
                "status": "pending",
                "requested_by": {"$ne": session["user_id"]}
            },
            {"student_name": 1, "roll_no": 1}
        )
    )

    # Create claim record
    claim_record = {
        "item_id": item_object_id,
        "item_name": item["name"],
        "item_description": item.get("description", ""),
        "category": item.get("category", ""),
        "location": item.get("location", ""),
        "student_name": student_name,
        "student_email": student_email,
        "roll_no": roll_no,
        "description_lost": description_lost,
        "status": "pending",
        "requested_at": datetime.utcnow(),
        "requested_by": session["user_id"]
    }

    try:
        # Insert a fresh dict so PyMongo's injected _id is never reused accidentally.
        claims_collection.insert_one(dict(claim_record))
    except DuplicateKeyError:
        existing = claims_collection.find_one({
            "item_id": item_object_id,
            "requested_by": session["user_id"],
            "status": "pending"
        })
        if existing:
            session["claim_error"] = "You already submitted a claim for this item."
        else:
            session["claim_error"] = "This claim could not be submitted right now. Please try again."
        return redirect(url_for("items"))

    prior_claimant_labels = []
    for previous_claim in previous_claims:
        previous_name = previous_claim.get("student_name") or "Unknown User"
        previous_roll_no = previous_claim.get("roll_no") or "--"
        prior_claimant_labels.append(f"{previous_name} ({previous_roll_no})")

    attention_note = ""
    if prior_claimant_labels:
        attention_note = " Extra attention: pending claim already exists from " + ", ".join(prior_claimant_labels) + "."

    # Notify ALL staff users about the new claim
    staff_users = list(users_collection.find({"role": "staff"}))
    for staff in staff_users:
        create_notification(
            str(staff["_id"]),
            "staff",
            f"New claim request from {student_name} ({roll_no}) for '{item['name']}'. Description: {description_lost}.{attention_note}",
            "claim_submitted"
        )

    session["claim_success"] = True
    return redirect(url_for("items"))
        

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
        description = request.form.get("description","")
        image = request.files.get("image")
        image_fields = _build_item_image_fields()

        if image and image.filename:
            image_bytes = image.read()
            image_fields = _build_item_image_fields(
                image_bytes=image_bytes,
                content_type=image.content_type,
                filename=image.filename,
            )

        item_document = {
            "name": name,
            "category": category,
            "type": "lost",
            "date": date,
            "location": location,
            "description": description,
            "status": "active",
            "reported_by": session["user_id"],
            "created_at": datetime.utcnow()
        }
        item_document.update(image_fields)

        items_collection.insert_one(item_document)

        # If admin submitted the report, notify all staff members
        if session.get("role") == "admin":
            # Get all staff user IDs
            staff_users = users_collection.find({"role": "staff"})
            for staff_user in staff_users:
                create_notification(
                    str(staff_user["_id"]),
                    "staff",
                    f"Administrator reported a lost item: '{name}'. Please assist if necessary.",
                    "admin_lost_report"
                )
            session["report_success"] = True
            return redirect(url_for("admin"))
        else:
            session["report_success"] = True
            return redirect(url_for("student"))

    return render_template("report_lost.html", categories=categories)

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

        image = request.files.get("image")
        image_fields = _build_item_image_fields()

        if image and image.filename:
            image_bytes = image.read()
            image_fields = _build_item_image_fields(
                image_bytes=image_bytes,
                content_type=image.content_type,
                filename=image.filename,
            )
        else:
            temp_upload_id = (request.form.get("uploaded_image") or session.get("uploaded_image_id") or "").strip()
            image_bytes, content_type, filename = _consume_temp_upload(temp_upload_id)
            if image_bytes:
                image_fields = _build_item_image_fields(
                    image_bytes=image_bytes,
                    content_type=content_type,
                    filename=filename,
                )

        # MongoDB item document
        item = {
            "name": name,
            "category": category,
            "type": type_,
            "date": date_combined,
            "location": location,
            "description": description,
            "status": "active",
            "reported_by": session["user_id"],
            "created_at": datetime.utcnow()
        }
        item.update(image_fields)

        items_collection.insert_one(item)

        _clear_uploaded_image_session()
        session.pop("visited_report_found", None)

        session["report_success"] = True
        return redirect(url_for("staff"))

    uploaded_image = session.get("uploaded_image_id")

    # Remove image if page reload happens
    if request.method == "GET" and session.get("visited_report_found"):
        _clear_uploaded_image_session()
        uploaded_image = None

    session["visited_report_found"] = True

    return render_template("report_found.html", uploaded_image=uploaded_image, categories=categories)

# ---------------- ITEMS ----------------
@app.route("/items")
def items():

    if "user" not in session:
        return redirect(url_for("login"))

    role = session.get("role")
    claim_success = session.pop("claim_success", False)
    claim_error = session.pop("claim_error", "")

    if role == "staff":
        items = list(items_collection.find({}, ITEM_LIST_PROJECTION).sort("created_at",-1).limit(50))
        return render_template("items_staff.html", items=items)

    else:
        # Students can see both lost and found active items
        items = list(items_collection.find({"status":"active"}, ITEM_LIST_PROJECTION).sort("created_at",-1).limit(50))
        return render_template("items_student.html", items=items, claim_success=claim_success, claim_error=claim_error)


@app.route("/item/<item_id>")
def item_details(item_id):
    if "user" not in session:
        return redirect(url_for("login"))

    role = session.get("role")
    context = _prepare_item_detail_context(item_id, role, session.get("user_id"))
    if not context:
        flash("Item not found.", "error")
        fallback = "admin" if role == "admin" else "items"
        return redirect(url_for(fallback))

    back_url = url_for("admin") if role == "admin" else url_for("items")
    back_label = "Admin Dashboard" if role == "admin" else "Items"

    return render_template(
        "item_details.html",
        item=context["item"],
        claims=context["claims"],
        user_claim=context["user_claim"],
        steps=context["steps"],
        view_mode="general",
        role=role,
        back_url=back_url,
        back_label=back_label,
    )


# ---------------- API ENDPOINTS ----------------
@app.route('/api/items/staff')
def api_items_staff():
    # Return JSON list of items for staff dashboard polling
    if "user" not in session or session.get("role") != "staff":
        return jsonify({"error": "unauthorized"}), 401

    items = list(items_collection.find({}, ITEM_LIST_PROJECTION).sort("created_at", -1).limit(200))

    def serialize(it):
        return {
            "_id": str(it.get("_id")),
            "name": it.get("name", ""),
            "type": it.get("type", ""),
            "category": it.get("category", ""),
            "status": it.get("status", ""),
            "date": it.get("date", ""),
            "location": it.get("location", ""),
        }

    return jsonify({"items": [serialize(i) for i in items]})



# ---------------- CAMERA ----------------
@app.route("/camera")
def camera():
    return_url = request.args.get("next", url_for("report_found"))
    return render_template("camera.html", return_url=return_url)

# ---------------- UPLOAD ----------------
@app.route("/upload", methods=["GET","POST"])
def upload():

    if request.method != "POST":
        return render_template("upload.html")

    file_id = None

    # 🔹 Camera (base64)
    image_data = request.form.get("image")

    if image_data:
        if not image_data.startswith("data:image"):
            return "Invalid image"

        header, encoded_data = image_data.split(",", 1)
        content_type = header.split(";")[0].split(":", 1)[1] if ":" in header else "image/png"
        image_bytes = base64.b64decode(encoded_data)
        file_id = _store_temp_upload(image_bytes, content_type)

    # 🔹 File upload
    elif "image" in request.files:
        image = request.files["image"]

        if image and image.filename:
            image_bytes = image.read()
            file_id = _store_temp_upload(image_bytes, image.content_type, image.filename)
        else:
            return "No image received"

    else:
        return "No image received"

    _clear_uploaded_image_session()
    session["uploaded_image_id"] = str(file_id)

    next_url = request.args.get("next") or url_for("report_found")
    return redirect(next_url)


@app.route("/image/<file_id>")
def get_image(file_id):
    temp_upload = _get_temp_upload(file_id)
    if temp_upload:
        return Response(
            bytes(temp_upload.get("image") or b""),
            mimetype=temp_upload.get("image_content_type") or DEFAULT_IMAGE_CONTENT_TYPE,
        )

    try:
        file = fs.get(ObjectId(file_id))
        return Response(file.read(), mimetype=file.content_type)
    except Exception:
        return "Image not found", 404


# ---------------- PREVIOUS ITEMS (STAFF) ----------------
@app.route("/previous-items")
def previous_items():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))

    items = list(archived_items_collection.find({}, ITEM_LIST_PROJECTION).sort("archived_at", -1).limit(50))
    return render_template("previous-items.html", items=items)

# ---------------- STUDENT HISTORY ----------------
@app.route("/student-history")
def student_history():
    if "user" not in session or session.get("role") != "student":
        return redirect(url_for("login"))

    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    student_email = user["email"]

    # Get all claims by this student
    student_claims = list(claims_collection.find({"requested_by": user_id}).sort("requested_at", -1))

    # Get archived items for this student
    archived = list(archived_items_collection.find({"claimed_by_email": student_email}, ITEM_LIST_PROJECTION).sort("archived_at", -1))

    # Check if student is flagged
    is_flagged = user.get("account_flagged", False)
    flag_reason = user.get("flag_reason", "")

    return render_template(
        "student_history.html",
        claims=student_claims,
        archived_items=archived,
        is_flagged=is_flagged,
        flag_reason=flag_reason
    )

# ---------------- MARK NOTIFICATION READ ----------------
@app.route("/mark-read/<notification_id>", methods=["POST"])
def mark_read(notification_id):
    if "user" not in session:
        return redirect(url_for("login"))

    notifications_collection.update_one(
        {"_id": ObjectId(notification_id)},
        {"$set": {"read": True}}
    )

    role = session.get("role")
    if role == "staff":
        return redirect(url_for("notifications"))
    else:
        return redirect(url_for("notification_student"))

# ---------------- DISMISS NOTIFICATION ----------------
@app.route("/dismiss-notification/<notification_id>", methods=["POST"])
def dismiss_notification(notification_id):
    if "user" not in session:
        return redirect(url_for("login"))

    notifications_collection.delete_one(
        {"_id": ObjectId(notification_id)}
    )

    role = session.get("role")
    if role == "staff":
        return redirect(url_for("notifications"))
    else:
        return redirect(url_for("notification_student"))

# ---------------- MARK ALL READ ----------------
@app.route("/mark-all-read", methods=["POST"])
def mark_all_read():
    if "user" not in session:
        return redirect(url_for("login"))

    user_id = str(session["user_id"])
    notifications_collection.update_many(
        {"user_id": user_id, "read": False},
        {"$set": {"read": True}}
    )

    role = session.get("role")
    if role == "staff":
        return redirect(url_for("notifications"))
    else:
        return redirect(url_for("notification_student"))

# to access the chatbot from templates
@app.route("/chatbot")
def chatbot_page():
    return render_template("Chatbot-1.html")

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True, port=5001, use_reloader=True)
