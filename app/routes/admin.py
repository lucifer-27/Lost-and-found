from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from bson.objectid import ObjectId
from ..extensions import users_collection, items_collection, claims_collection, archived_items_collection, item_reports_collection
from ..utils.helpers import (
    create_notification, get_user_display_fields, find_user_by_id,
    prepare_item_detail_context, ITEM_LIST_PROJECTION,
    REPORT_CATEGORIES, REPORT_RESOLUTION_STATUSES,
)

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin")
def admin_dashboard():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("auth.login"))

    flag_success = session.pop("flag_success", None)
    report_success = session.pop("report_success", None)

    # 1. System Activity Monitoring Stats
    total_active_items = items_collection.count_documents({"status": "active"})
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

    # 2. User Information Management
    users = list(users_collection.find({"account_flagged": {"$ne": True}}).sort("_id", -1))

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

    # Pending Reports
    pending_reports = list(items_collection.find({"status": "active"}, ITEM_LIST_PROJECTION).sort("created_at", -1).limit(10))
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


@admin_bp.route("/admin/user/<user_id>")
def admin_user_details(user_id):
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("auth.login"))

    try:
        inspected_user = users_collection.find_one({"_id": ObjectId(user_id)})
    except Exception:
        inspected_user = None

    if not inspected_user:
        flash("User not found.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    user_items = list(items_collection.find({"reported_by": user_id}, ITEM_LIST_PROJECTION)) + list(archived_items_collection.find({"reported_by": user_id}, ITEM_LIST_PROJECTION))
    user_items.sort(key=lambda x: x.get("created_at") or datetime.min, reverse=True)

    user_claims = list(claims_collection.find({"requested_by": user_id}).sort("requested_at", -1))
    for claim in user_claims:
        try:
            item = items_collection.find_one({"_id": ObjectId(claim["item_id"])}) or archived_items_collection.find_one({"_id": ObjectId(claim["item_id"])})
            claim["item_name"] = item["name"] if item else "Unknown Item"
        except Exception:
            claim["item_name"] = "Unknown Item"

        if claim.get("processed_by"):
            try:
                staff = users_collection.find_one({"_id": ObjectId(claim["processed_by"])})
                claim["staff_email"] = staff["email"] if staff else "Unknown Staff"
            except Exception:
                claim["staff_email"] = "Unknown Staff"

    return render_template(
        "admin_user_details.html",
        inspected_user=inspected_user,
        user_items=user_items,
        user_claims=user_claims,
        flag_success=session.pop("flag_success", None)
    )


@admin_bp.route("/admin/item/<item_id>")
def admin_item_status(item_id):
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("auth.login"))

    context = prepare_item_detail_context(item_id, "admin", session.get("user_id"))
    if not context:
        flash("Item not found.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    return render_template(
        "item_details.html",
        item=context["item"],
        claims=context["claims"],
        user_claim=context["user_claim"],
        steps=context["steps"],
        view_mode="admin",
        role="admin",
        back_url=url_for("admin.admin_dashboard"),
        back_label="Admin Dashboard",
    )


@admin_bp.route("/admin/flagged-users")
def flagged_users():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("auth.login"))

    users = list(users_collection.find({"account_flagged": True}).sort("_id", -1))
    return render_template("flagged_users.html", users=users)


@admin_bp.route("/admin/item-reports")
def admin_item_reports():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("auth.login"))

    status_filter = request.args.get("status", "open")
    if status_filter not in REPORT_RESOLUTION_STATUSES:
        status_filter = "open"

    reports = list(
        item_reports_collection.find({"status": status_filter}).sort("created_at", -1).limit(200)
    )

    for report in reports:
        reporter_fields = get_user_display_fields(find_user_by_id(report.get("reported_by")))
        report["reporter_name"] = reporter_fields["name"]
        report["reporter_roll_no"] = reporter_fields["roll_no"]

        item = None
        item_id_value = report.get("item_id")
        try:
            item_obj_id = ObjectId(item_id_value)
            item = items_collection.find_one({"_id": item_obj_id}) or archived_items_collection.find_one({"_id": item_obj_id})
        except Exception:
            item = None
        report["item_status"] = item.get("status") if item else "unknown"

    return render_template(
        "admin_item_reports.html",
        reports=reports,
        status_filter=status_filter,
        report_categories=REPORT_CATEGORIES,
    )


@admin_bp.route("/admin/item-reports/<report_id>/resolve", methods=["POST"])
def resolve_item_report(report_id):
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("auth.login"))

    resolution_status = request.form.get("resolution_status", "dismissed")
    resolution_note = (request.form.get("resolution_note") or "").strip()
    mark_under_review = request.form.get("mark_under_review") == "on"
    flag_reporter = request.form.get("flag_reporter") == "on"

    if resolution_status not in REPORT_RESOLUTION_STATUSES:
        resolution_status = "dismissed"

    try:
        report_obj_id = ObjectId(report_id)
    except Exception:
        return redirect(url_for("admin.admin_item_reports"))

    report = item_reports_collection.find_one({"_id": report_obj_id})
    if not report:
        return redirect(url_for("admin.admin_item_reports"))

    update_doc = {
        "status": resolution_status,
        "resolved_at": datetime.utcnow(),
        "resolved_by": str(session.get("user_id")),
        "resolution_note": resolution_note,
    }
    item_reports_collection.update_one({"_id": report_obj_id}, {"$set": update_doc})

    item = None
    try:
        item = items_collection.find_one({"_id": ObjectId(report.get("item_id"))})
    except Exception:
        item = None

    if mark_under_review and item:
        items_collection.update_one(
            {"_id": item["_id"]},
            {"$set": {"status": "under_review"}}
        )

    if flag_reporter and item:
        reporter_id = item.get("reported_by")
        if reporter_id:
            try:
                reporter_obj_id = ObjectId(reporter_id)
            except Exception:
                reporter_obj_id = reporter_id
            users_collection.update_one(
                {"_id": reporter_obj_id},
                {"$set": {"account_flagged": True}}
            )
            create_notification(
                str(reporter_id),
                "student",
                "Your account has been flagged due to a reported item. Please contact the admin for details.",
                "account_flagged"
            )

    reporter_id = report.get("reported_by")
    if reporter_id:
        create_notification(
            str(reporter_id),
            "student" if report.get("reporter_role") == "student" else "staff",
            f"Your item report has been reviewed and marked as {resolution_status}.",
            "item_report_reviewed",
        )

    return redirect(url_for("admin.admin_item_reports", status=resolution_status))


@admin_bp.route("/admin/toggle-flag/<user_id>", methods=["POST"])
def toggle_flag(user_id):
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("auth.login"))

    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if user:
        if user.get("role") == "admin":
            session["flag_success"] = "Admin accounts cannot be flagged."
            return redirect(request.referrer or url_for("admin.admin_dashboard"))

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

        status_text = "flagged" if new_status else "unflagged"
        create_notification(
            str(user["_id"]),
            "student" if user.get("role") == "student" else "staff",
            f"Your account has been {status_text} by the administrator.",
            "account_flagged" if new_status else "account_unflagged"
        )

    return redirect(request.referrer or url_for("admin.admin_dashboard"))
