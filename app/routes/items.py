from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, flash
from app.extensions import limiter
from bson.objectid import ObjectId
from pymongo.errors import DuplicateKeyError
from ..extensions import users_collection, items_collection, claims_collection, archived_items_collection, item_reports_collection
from ..utils.helpers import (
    create_notification, create_bulk_notifications, categories, parse_submitted_date,
    prepare_item_detail_context, ITEM_LIST_PROJECTION, check_idempotency,
    REPORT_CATEGORIES, build_duplicate_fingerprint, find_possible_duplicate,
)
from ..services.image_service import build_item_image_fields, consume_temp_upload
from ..models.item_model import new_item, new_claim

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
    report_success = session.pop("item_report_success", None)
    report_error = session.pop("item_report_error", None)
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
        report_target_id=context.get("report_target_id"),
        user_report=context.get("user_report"),
        report_success=report_success,
        report_error=report_error,
        view_mode="general",
        role=role,
        back_url=back_url,
        back_label=back_label,
    )


@items_bp.route("/report-item/<item_id>", methods=["POST"])
def report_item(item_id):
    if "user" not in session:
        return redirect(url_for("auth.login"))

    next_url = request.form.get("next") or url_for("items.item_details", item_id=item_id)
    reason = (request.form.get("reason") or "").strip()
    category = (request.form.get("category") or "").strip()

    if not reason:
        session["item_report_error"] = "Please provide a short reason for reporting this item."
        return redirect(next_url)
        
    idempotency_key = f"report_item_{item_id}_{session.get('user_id')}"
    if not check_idempotency(session, idempotency_key):
        return redirect(next_url)

    if category not in REPORT_CATEGORIES:
        category = "Other"

    context = prepare_item_detail_context(item_id, session.get("role"), session.get("user_id"))
    if not context or not context.get("report_target_id"):
        session["item_report_error"] = "Unable to find this item for reporting."
        return redirect(next_url)

    reporter_id = str(session.get("user_id"))
    existing = item_reports_collection.find_one({
        "item_id": context["report_target_id"],
        "reported_by": reporter_id,
        "status": "open",
    })
    if existing:
        session["item_report_error"] = "You already reported this item. Our team will review it."
        return redirect(next_url)

    report_doc = {
        "item_id": context["report_target_id"],
        "item_name": context["item"].get("name", ""),
        "item_type": context["item"].get("type", ""),
        "item_category": context["item"].get("category", ""),
        "item_location": context["item"].get("location", ""),
        "reported_by": reporter_id,
        "reporter_role": session.get("role"),
        "category": category,
        "reason": reason,
        "status": "open",
        "created_at": datetime.utcnow(),
    }
    item_reports_collection.insert_one(report_doc)

    admin_users = list(users_collection.find({"role": "admin"}, {"_id": 1}))
    admin_ids = [str(u["_id"]) for u in admin_users]
    create_bulk_notifications(
        admin_ids,
        "admin",
        f"New item report: '{context['item'].get('name', 'Unknown Item')}' ({category}).",
        "item_report",
    )

    session["item_report_success"] = "Report submitted. Admins will review it shortly."
    return redirect(next_url)


@items_bp.route("/request-claim", methods=["POST"])
def request_claim():
    if "user" not in session or session.get("role") != "student":
        return redirect(url_for("auth.login"))

    user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
    if not user:
        session["claim_error"] = "Your account could not be verified. Please log in again."
        return redirect(url_for("auth.login"))

    if user.get("account_flagged", False):
        session["claim_error"] = "Your account is flagged. You cannot submit new claims at this time."
        return redirect(url_for("items.items_list"))

    item_id = (request.form.get("item_id") or "").strip()
    student_name = (request.form.get("student_name") or "").strip()
    description_lost = (request.form.get("description_lost") or "").strip()

    if not item_id:
        return redirect(url_for("items.items_list"))

    if not student_name or not description_lost:
        session["claim_error"] = "Please fill in your name and item description before submitting."
        return redirect(url_for("items.items_list"))
        
    idempotency_key = f"claim_{item_id}_{session.get('user_id')}"
    if not check_idempotency(session, idempotency_key):
        return redirect(url_for("items.items_list"))

    try:
        item_object_id = ObjectId(item_id)
    except Exception:
        session["claim_error"] = "Invalid item selected."
        return redirect(url_for("items.items_list"))


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

    claim_record = new_claim(
        item_id=item_object_id,
        item=item,
        student_name=student_name,
        student_email=student_email,
        roll_no=roll_no,
        description_lost=description_lost,
        requested_by=session["user_id"]
    )

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

    staff_users = list(users_collection.find({"role": "staff"}, {"_id": 1}))
    staff_ids = [str(u["_id"]) for u in staff_users]
    create_bulk_notifications(
        staff_ids,
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

    user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
    if user and user.get("account_flagged", False):
        flash("Your account is flagged. You cannot report lost items at this time.", "error")
        return redirect(url_for("items.items_list"))

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

        dup_fingerprint = build_duplicate_fingerprint(name, category, location, "lost", date)
        
        idempotency_key = f"lost_{dup_fingerprint}_{session.get('user_id')}"
        if not check_idempotency(session, idempotency_key):
            session["report_success"] = True
            return redirect(url_for("student.student_dashboard") if session.get("role") != "admin" else url_for("admin.admin_dashboard"))

        existing, same_reporter = find_possible_duplicate(dup_fingerprint, session.get("user_id"))
        if same_reporter:
            return render_template(
                "report_lost.html",
                categories=categories,
                today=today_str,
                error="You already reported a very similar lost item. If this is different, please add more specific details.",
            )

        if image and image.filename:
            image_bytes = image.read()
            try:
                image_fields = build_item_image_fields(
                    image_bytes=image_bytes, content_type=image.content_type, filename=image.filename)
            except ValueError as e:
                return render_template("report_lost.html", categories=categories, today=today_str,
                                       error=str(e))

        item_document = new_item(
            name=name, category=category, item_type="lost",
            date=date, location=location, description=description,
            reported_by=session["user_id"],
            dup_fingerprint=dup_fingerprint,
            is_possible_duplicate=bool(existing),
            duplicate_of=existing["_id"] if existing else None,
            image_fields=image_fields
        )
        items_collection.insert_one(item_document)

        if existing:
            admin_users = list(users_collection.find({"role": "admin"}, {"_id": 1}))
            admin_ids = [str(u["_id"]) for u in admin_users]
            create_bulk_notifications(
                admin_ids,
                "admin",
                f"Possible duplicate lost item report: '{name}'.",
                "duplicate_report",
            )

        if session.get("role") == "admin":
            staff_users = list(users_collection.find({"role": "staff"}, {"_id": 1}))
            staff_ids = [str(u["_id"]) for u in staff_users]
            create_bulk_notifications(
                staff_ids, "staff",
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
@limiter.limit("5 per minute")
def report_found():
    if "user" not in session:
        return redirect(url_for("auth.login"))

    user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
    if user and user.get("account_flagged", False):
        flash("Your account is flagged. You cannot report found items at this time.", "error")
        return redirect(url_for("items.items_list"))

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
                uploaded_image=(request.form.get("uploaded_image") or request.args.get("upload_id") or "").strip() or None,
                categories=categories, today=today_str, error="Please select a valid found date.")

        if selected_date > today:
            return render_template("report_found.html",
                uploaded_image=(request.form.get("uploaded_image") or request.args.get("upload_id") or "").strip() or None,
                categories=categories, today=today_str, error="Found date cannot be in the future.")

        date_combined = f"{date} {time_found}" if time_found else date

        dup_fingerprint = build_duplicate_fingerprint(name, category, location, "found", date_combined)
        
        idempotency_key = f"found_{dup_fingerprint}_{session.get('user_id')}"
        if not check_idempotency(session, idempotency_key):
            session["report_success"] = True
            return redirect(url_for("staff.staff_dashboard"))

        existing, same_reporter = find_possible_duplicate(dup_fingerprint, session.get("user_id"))
        if same_reporter:
            return render_template(
                "report_found.html",
                uploaded_image=(request.form.get("uploaded_image") or request.args.get("upload_id") or "").strip() or None,
                categories=categories,
                today=today_str,
                error="You already reported a very similar found item. If this is different, please add more specific details.",
            )

        try:
            if image and image.filename:
                image_bytes = image.read()
                image_fields = build_item_image_fields(
                    image_bytes=image_bytes, content_type=image.content_type, filename=image.filename)
            else:
                temp_upload_id = (request.form.get("uploaded_image") or request.args.get("upload_id") or "").strip()
                image_bytes, content_type, filename = consume_temp_upload(temp_upload_id)
                if image_bytes:
                    image_fields = build_item_image_fields(
                        image_bytes=image_bytes, content_type=content_type, filename=filename)
        except ValueError as e:
            return render_template("report_found.html",
                uploaded_image=(request.form.get("uploaded_image") or request.args.get("upload_id") or "").strip() or None,
                categories=categories, today=today_str, error=str(e))

        item = new_item(
            name=name, category=category, item_type="found",
            date=date_combined, location=location, description=description,
            reported_by=session["user_id"],
            dup_fingerprint=dup_fingerprint,
            is_possible_duplicate=bool(existing),
            duplicate_of=existing["_id"] if existing else None,
            image_fields=image_fields
        )
        items_collection.insert_one(item)

        if existing:
            admin_users = list(users_collection.find({"role": "admin"}, {"_id": 1}))
            admin_ids = [str(u["_id"]) for u in admin_users]
            create_bulk_notifications(
                admin_ids,
                "admin",
                f"Possible duplicate found item report: '{name}'.",
                "duplicate_report",
            )

        session["report_success"] = True
        return redirect(url_for("staff.staff_dashboard"))

    uploaded_image = request.args.get("upload_id")
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
