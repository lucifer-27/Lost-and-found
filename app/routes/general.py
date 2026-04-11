import base64
import smtplib
import os
from email.mime.text import MIMEText
from flask import Blueprint, render_template, request, redirect, url_for, session, Response
from bson.objectid import ObjectId
from ..extensions import items_collection, notifications_collection
from ..utils.helpers import ITEM_LIST_PROJECTION
from ..services.image_service import (
    DEFAULT_IMAGE_CONTENT_TYPE, get_temp_upload, store_temp_upload,
    delete_temp_upload,
)


def send_contact_email(to_email, subject, body):
    """Send contact form emails"""
    try:
        smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
        smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        smtp_username = os.environ.get("SMTP_USERNAME", "").strip() or os.environ.get("EMAIL", "").strip()
        smtp_password = os.environ.get("SMTP_PASSWORD", "").strip() or os.environ.get("EMAIL_PASS", "").strip()
        from_email = os.environ.get("SMTP_FROM_EMAIL", "").strip() or smtp_username
        
        if not all([smtp_host, smtp_username, smtp_password, from_email]):
            print("Email configuration missing")
            return False, "SMTP configuration is missing. Please contact support via Twitter/X."
            
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = to_email
        
        # Safely force IPv4 by overriding the socket creation for this specific SMTP instance
        # This prevents process-wide monkey-patching which causes race conditions.
        import socket
        class IPv4SMTP(smtplib.SMTP):
            def _get_socket(self, host, port, timeout):
                err = None
                for res in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
                    af, socktype, proto, canonname, sa = res
                    try:
                        sock = socket.socket(af, socktype, proto)
                        if self.timeout is not getattr(socket, '_GLOBAL_DEFAULT_TIMEOUT', object()):
                            sock.settimeout(self.timeout)
                        if self.source_address:
                            sock.bind(self.source_address)
                        sock.connect(sa)
                        return sock
                    except OSError as _:
                        err = _
                        if sock is not None:
                            sock.close()
                if err is not None:
                    raise err
                raise OSError("getaddrinfo returns an empty list")

        with IPv4SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        
        print(f"Contact email sent successfully to {to_email}")
        return True, ""
    except Exception as e:
        error_details = f"SMTP Error: {str(e)}"
        print(f"Error sending contact email: {error_details}")
        return False, error_details

general_bp = Blueprint("general", __name__)


@general_bp.route("/")
def home():
    items = list(items_collection.find({"status": "active"}, ITEM_LIST_PROJECTION).sort("created_at", -1).limit(4))
    return render_template("index.html", recent_items=items)

@general_bp.route("/privacy_policy")
def privacy_policy():
    return render_template("privacy_policy.html")

@general_bp.route("/contact", methods=["GET", "POST"])
@general_bp.route("/contact-us", methods=["GET", "POST"])
@general_bp.route("/support", methods=["GET", "POST"])
def contact():
    """Handle contact form submissions - accessible to all users"""
    success_message = None
    error_message = None
    
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        # Validate inputs
        if not all([name, email, subject, message]):
            error_message = "All fields are required."
        elif len(message) < 10:
            error_message = "Message must be at least 10 characters long."
        else:
            try:
                # Send email to support
                email_subject = f"CampusFind Support: {subject}"
                send_email_body = f"""
New message from CampusFind Contact Form:

Name: {name}
Email: {email}
Subject: {subject}

Message:
{message}

---
Reply to: {email}
                """

                import threading
                # Offload email sending to a background thread to prevent blocking
                threading.Thread(
                    target=send_contact_email,
                    kwargs={
                        "to_email": "campusfind.lnf@gmail.com",
                        "subject": email_subject,
                        "body": send_email_body
                    },
                    daemon=True
                ).start()
                
                success_message = "Your message has been sent successfully! We'll get back to you soon."
                name = email = subject = message = ""  # Clear form

            except Exception as e:
                print(f"Error sending contact email: {str(e)}")
                error_message = "Failed to send message. Please try again or email us directly at campusfind.lnf@gmail.com"

    return render_template("contact.html", success_message=success_message, error_message=error_message)


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
    {
        "_id": ObjectId(notification_id),
        "user_id": str(session["user_id"])
    },
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
    notifications_collection.delete_one({
    "_id": ObjectId(notification_id),
    "user_id": str(session["user_id"])
    })
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

    from flask import flash
    try:
        # Camera (base64)
        image_data = request.form.get("image")
        if image_data:
            if not image_data.startswith("data:image"):
                flash("Invalid image payload", "error")
                return redirect(request.args.get("next") or url_for("items.report_found"))
            try:
                header, encoded_data = image_data.split(",", 1)
                content_type = header.split(";")[0].split(":", 1)[1] if ":" in header else "image/png"
                image_bytes = base64.b64decode(encoded_data, validate=True)
            except Exception:
                flash("Corrupted image data", "error")
                return redirect(request.args.get("next") or url_for("items.report_found"))
            file_id = store_temp_upload(image_bytes, content_type)

        # File upload
        elif "image" in request.files:
            image = request.files["image"]
            if image and image.filename:
                image_bytes = image.read()
                file_id = store_temp_upload(image_bytes, image.content_type, image.filename)
            else:
                flash("No image received", "error")
                return redirect(request.args.get("next") or url_for("items.report_found"))
        else:
            flash("No image received", "error")
            return redirect(request.args.get("next") or url_for("items.report_found"))
            
    except ValueError as e:
        flash(str(e), "error")
        return redirect(request.args.get("next") or url_for("items.report_found"))

    next_url = request.args.get("next") or url_for("items.report_found")
    if "?" in next_url:
        return redirect(f"{next_url}&upload_id={file_id}")
    else:
        return redirect(f"{next_url}?upload_id={file_id}")


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
