import base64
from flask import Blueprint, render_template, request, redirect, url_for, session, Response
from bson.objectid import ObjectId
from ..extensions import items_collection, notifications_collection
from ..utils.helpers import ITEM_LIST_PROJECTION
from ..services.image_service import (
    DEFAULT_IMAGE_CONTENT_TYPE, get_temp_upload, store_temp_upload,
    delete_temp_upload,
)

general_bp = Blueprint("general", __name__)


@general_bp.route("/")
def home():
    items = list(items_collection.find({"status": "active"}, ITEM_LIST_PROJECTION).sort("created_at", -1).limit(4))
    return render_template("index.html", recent_items=items)


# ---------- NOTIFICATIONS ----------

@general_bp.route("/notification_student")
def notification_student():
    if "user" not in session or session.get("role") != "student":
        return redirect(url_for("auth.login"))
    user_id = str(session["user_id"])
    notifications = list(notifications_collection.find({"user_id": user_id}).sort("created_at", -1))
    return render_template("notification_student.html", notifications=notifications)


@general_bp.route("/notifications")
def notifications():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("auth.login"))
    user_id = str(session["user_id"])
    notifications = list(notifications_collection.find({"user_id": user_id}).sort("created_at", -1))
    return render_template("notification_staff.html", notifications=notifications)


@general_bp.route("/notifications-admin")
def notifications_admin():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("auth.login"))
    user_id = str(session["user_id"])
    notifications = list(notifications_collection.find({"user_id": user_id}).sort("created_at", -1))
    return render_template("notification_staff.html", notifications=notifications)


@general_bp.route("/mark-read/<notification_id>", methods=["POST"])
def mark_read(notification_id):
    if "user" not in session:
        return redirect(url_for("auth.login"))
    notifications_collection.update_one(
        {"_id": ObjectId(notification_id)},
        {"$set": {"read": True}}
    )
    role = session.get("role")
    if role == "staff":
        return redirect(url_for("general.notifications"))
    else:
        return redirect(url_for("general.notification_student"))


@general_bp.route("/dismiss-notification/<notification_id>", methods=["POST"])
def dismiss_notification(notification_id):
    if "user" not in session:
        return redirect(url_for("auth.login"))
    notifications_collection.delete_one({"_id": ObjectId(notification_id)})
    role = session.get("role")
    if role == "staff":
        return redirect(url_for("general.notifications"))
    else:
        return redirect(url_for("general.notification_student"))


@general_bp.route("/mark-all-read", methods=["POST"])
def mark_all_read():
    if "user" not in session:
        return redirect(url_for("auth.login"))
    user_id = str(session["user_id"])
    notifications_collection.update_many(
        {"user_id": user_id, "read": False},
        {"$set": {"read": True}}
    )
    role = session.get("role")
    if role == "staff":
        return redirect(url_for("general.notifications"))
    else:
        return redirect(url_for("general.notification_student"))


# ---------- CAMERA / UPLOAD / IMAGE ----------

@general_bp.route("/camera")
def camera():
    return_url = request.args.get("next", url_for("items.report_found"))
    return render_template("camera.html", return_url=return_url)


@general_bp.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method != "POST":
        return render_template("upload.html")

    file_id = None

    # Camera (base64)
    image_data = request.form.get("image")
    if image_data:
        if not image_data.startswith("data:image"):
            return "Invalid image"
        header, encoded_data = image_data.split(",", 1)
        content_type = header.split(";")[0].split(":", 1)[1] if ":" in header else "image/png"
        image_bytes = base64.b64decode(encoded_data)
        file_id = store_temp_upload(image_bytes, content_type)

    # File upload
    elif "image" in request.files:
        image = request.files["image"]
        if image and image.filename:
            image_bytes = image.read()
            file_id = store_temp_upload(image_bytes, image.content_type, image.filename)
        else:
            return "No image received"
    else:
        return "No image received"

    # Clear any previous upload
    session.pop("show_uploaded_image_preview_once", None)
    old_upload_id = session.pop("uploaded_image_id", None)
    if old_upload_id:
        delete_temp_upload(old_upload_id)

    session["uploaded_image_id"] = str(file_id)
    session["show_uploaded_image_preview_once"] = True

    next_url = request.args.get("next") or url_for("items.report_found")
    return redirect(next_url)


@general_bp.route("/image/<file_id>")
def get_image(file_id):
    from ..extensions import fs

    temp_upload = get_temp_upload(file_id)
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


# ---------- CHATBOT ----------

@general_bp.route("/chatbot")
def chatbot_page():
    return render_template("Chatbot-1.html")
