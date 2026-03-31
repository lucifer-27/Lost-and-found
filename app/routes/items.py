from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, flash
from bson.objectid import ObjectId
from pymongo.errors import DuplicateKeyError
from ..extensions import users_collection, items_collection, claims_collection, archived_items_collection
from ..utils.helpers import (
    create_notification, categories, parse_submitted_date,
    prepare_item_detail_context, ITEM_LIST_PROJECTION,
)
from ..services.image_service import build_item_image_fields, consume_temp_upload

items_bp = Blueprint("items", __name__)


@items_bp.route("/items")
def items_list():
    if "user" not in session:
        return redirect(url_for("auth.login"))

    role = session.get("role")
    claim_success = session.pop("claim_success", False)
    claim_error = session.pop("claim_error", "")

    if role == "staff":
        items = list(items_collection.find({}, ITEM_LIST_PROJECTION).sort("created_at", -1).limit(50))
        return render_template("items_staff.html", items=items)
    else:
        items = list(items_collection.find({"status": "active"}, ITEM_LIST_PROJECTION).sort("created_at", -1).limit(50))
        return render_template("items_student.html", items=items, claim_success=claim_success, claim_error=claim_error)


@items_bp.route("/item/<item_id>")
def item_details(item_id):
    if "user" not in session:
        return redirect(url_for("auth.login"))

    role = session.get("role")
    context = prepare_item_detail_context(item_id, role, session.get("user_id"))
    if not context:
        flash("Item not found.", "error")
        fallback = "admin.admin_dashboard" if role == "admin" else "items.items_list"
        return redirect(url_for(fallback))

    back_url = url_for("admin.admin_dashboard") if role == "admin" else url_for("items.items_list")
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


@items_bp.route("/request-claim", methods=["POST"])
def request_claim():
    if "user" not in session or session.get("role") != "student":
        return redirect(url_for("auth.login"))

    item_id = (request.form.get("item_id") or "").strip()
    student_name = (request.form.get("student_name") or "").strip()
    description_lost = (request.form.get("description_lost") or "").strip()

    if not item_id:
        return redirect(url_for("items.items_list"))

    if not student_name or not description_lost:
        session["claim_error"] = "Please fill in your name and item description before submitting."
        return redirect(url_for("items.items_list"))

    try:
        item_object_id = ObjectId(item_id)
    except Exception:
        session["claim_error"] = "Invalid item selected."
        return redirect(url_for("items.items_list"))

    user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
    if not user:
        session["claim_error"] = "Your account could not be verified. Please log in again."
        return redirect(url_for("auth.login"))

    student_email = user["email"]
    roll_no = student_email.split("@")[0]

    item = items_collection.find_one({"_id": item_object_id})
    if not item:
        session["claim_error"] = "This item is no longer available for claim."
        return redirect(url_for("items.items_list"))

    existing = claims_collection.find_one({
        "item_id": item_object_id,
        "requested_by": session["user_id"],
        "status": "pending"
    })
    if existing:
        session["claim_error"] = "You already submitted a claim for this item."
        return redirect(url_for("items.items_list"))

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
        return redirect(url_for("items.items_list"))

    prior_claimant_labels = []
    for previous_claim in previous_claims:
        previous_name = previous_claim.get("student_name") or "Unknown User"
        previous_roll_no = previous_claim.get("roll_no") or "--"
        prior_claimant_labels.append(f"{previous_name} ({previous_roll_no})")

    attention_note = ""
    if prior_claimant_labels:
        attention_note = " Extra attention: pending claim already exists from " + ", ".join(prior_claimant_labels) + "."

    staff_users = list(users_collection.find({"role": "staff"}))
    for staff in staff_users:
        create_notification(
            str(staff["_id"]),
            "staff",
            f"New claim request from {student_name} ({roll_no}) for '{item['name']}'. Description: {description_lost}.{attention_note}",
            "claim_submitted"
        )

    session["claim_success"] = True
    return redirect(url_for("items.items_list"))


@items_bp.route("/report-lost", methods=["GET", "POST"])
def report_lost():
    if "user" not in session:
        return redirect(url_for("auth.login"))

    today = datetime.now().date()
    today_str = today.isoformat()

    if request.method == "POST":
        name = request.form.get("item_name")
        category = request.form.get("category")
        date = request.form.get("date_lost")
        location = request.form.get("location")
        description = request.form.get("description", "")
        image = request.files.get("image")
        image_fields = build_item_image_fields()
        selected_date = parse_submitted_date(date)

        if not selected_date:
            return render_template("report_lost.html", categories=categories, today=today_str,
                                   error="Please select a valid lost date.")

        if selected_date > today:
            return render_template("report_lost.html", categories=categories, today=today_str,
                                   error="Lost date cannot be in the future.")

        if image and image.filename:
            image_bytes = image.read()
            image_fields = build_item_image_fields(
                image_bytes=image_bytes, content_type=image.content_type, filename=image.filename)

        item_document = {
            "name": name, "category": category, "type": "lost",
            "date": date, "location": location, "description": description,
            "status": "active", "reported_by": session["user_id"],
            "created_at": datetime.utcnow()
        }
        item_document.update(image_fields)
        items_collection.insert_one(item_document)

        if session.get("role") == "admin":
            staff_users = users_collection.find({"role": "staff"})
            for staff_user in staff_users:
                create_notification(
                    str(staff_user["_id"]), "staff",
                    f"Administrator reported a lost item: '{name}'. Please assist if necessary.",
                    "admin_lost_report"
                )
            session["report_success"] = True
            return redirect(url_for("admin.admin_dashboard"))
        else:
            session["report_success"] = True
            return redirect(url_for("student.student_dashboard"))

    return render_template("report_lost.html", categories=categories, today=today_str)


@items_bp.route("/report-found", methods=["GET", "POST"])
def report_found():
    if "user" not in session:
        return redirect(url_for("auth.login"))

    today = datetime.now().date()
    today_str = today.isoformat()

    if request.method == "POST":
        name = request.form.get("item_name")
        category = request.form.get("category")
        date = request.form.get("date_found")
        time_found = request.form.get("time_found")
        location = request.form.get("location")
        description = request.form.get("description")
        selected_date = parse_submitted_date(date)

        if not selected_date:
            return render_template("report_found.html",
                uploaded_image=(request.form.get("uploaded_image") or session.get("uploaded_image_id") or "").strip() or None,
                categories=categories, today=today_str, error="Please select a valid found date.")

        if selected_date > today:
            return render_template("report_found.html",
                uploaded_image=(request.form.get("uploaded_image") or session.get("uploaded_image_id") or "").strip() or None,
                categories=categories, today=today_str, error="Found date cannot be in the future.")

        date_combined = f"{date} {time_found}" if time_found else date

        image = request.files.get("image")
        image_fields = build_item_image_fields()

        if image and image.filename:
            image_bytes = image.read()
            image_fields = build_item_image_fields(
                image_bytes=image_bytes, content_type=image.content_type, filename=image.filename)
        else:
            temp_upload_id = (request.form.get("uploaded_image") or session.get("uploaded_image_id") or "").strip()
            image_bytes, content_type, filename = consume_temp_upload(temp_upload_id)
            if image_bytes:
                image_fields = build_item_image_fields(
                    image_bytes=image_bytes, content_type=content_type, filename=filename)

        item = {
            "name": name, "category": category, "type": "found",
            "date": date_combined, "location": location, "description": description,
            "status": "active", "reported_by": session["user_id"],
            "created_at": datetime.utcnow()
        }
        item.update(image_fields)
        items_collection.insert_one(item)

        # Clear uploaded image session
        session.pop("show_uploaded_image_preview_once", None)
        upload_id = session.pop("uploaded_image_id", None)
        if upload_id:
            from ..services.image_service import delete_temp_upload
            delete_temp_upload(upload_id)

        session["report_success"] = True
        return redirect(url_for("staff.staff_dashboard"))

    show_uploaded_image_preview = session.pop("show_uploaded_image_preview_once", False)
    uploaded_image = session.get("uploaded_image_id") if show_uploaded_image_preview else None

    if not show_uploaded_image_preview and session.get("uploaded_image_id"):
        session.pop("show_uploaded_image_preview_once", None)
        upload_id = session.pop("uploaded_image_id", None)
        if upload_id:
            from ..services.image_service import delete_temp_upload
            delete_temp_upload(upload_id)

    return render_template("report_found.html", uploaded_image=uploaded_image, categories=categories, today=today_str)


@items_bp.route("/api/items/staff")
def api_items_staff():
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
