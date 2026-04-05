from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, session
from bson.objectid import ObjectId
from ..extensions import users_collection, items_collection, claims_collection, archived_items_collection
from ..utils.helpers import create_notification, ITEM_LIST_PROJECTION

staff_bp = Blueprint("staff", __name__)


@staff_bp.route("/staff")
def staff_dashboard():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("auth.login"))
    report_success = session.pop("report_success", False)
    return render_template("staff.html", report_success=report_success)


@staff_bp.route("/pending-claims")
def pending_claims():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("auth.login"))
    claims = list(claims_collection.find({"status": "pending"}))
    return render_template("pending_claims.html", claims=claims)


@staff_bp.route("/process-claim/<claim_id>", methods=["GET", "POST"])
def process_claim(claim_id):
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("auth.login"))
    try:
        claim_obj_id = ObjectId(claim_id)
    except Exception:
        from flask import flash
        flash("Invalid claim ID format.", "error")
        return redirect(url_for("staff.pending_claims"))
        
    claim = claims_collection.find_one({"_id": claim_obj_id})
    if not claim:
        from flask import flash
        flash("Claim not found.", "error")
        return redirect(url_for("staff.pending_claims"))
    if request.method == "GET":
        return render_template("claim.html", claim=claim)
    proof = request.form.get("proof")
    return_date = request.form.get("return_date")
    return_time = request.form.get("return_time")
    claims_collection.update_one({"_id": ObjectId(claim_id)}, {"$set": {
        "status": "returned", "processed_by": session["user_id"],
        "processed_at": datetime.utcnow(), "proof": proof,
        "return_date": f"{return_date} {return_time}"
    }})
    items_collection.update_one({"_id": claim["item_id"]}, {"$set": {"status": "returned"}})
    item = items_collection.find_one({"_id": claim["item_id"]})
    if item:
        archived_items_collection.insert_one({
            "original_item_id": item["_id"], "name": item.get("name", ""),
            "category": item.get("category", ""), "type": item.get("type", ""),
            "date": item.get("date", ""), "location": item.get("location", ""),
            "description": item.get("description", ""),
            "image": item.get("image"), "image_content_type": item.get("image_content_type"),
            "image_filename": item.get("image_filename"), "image_id": item.get("image_id"),
            "reported_by": item.get("reported_by", ""),
            "claimed_by_name": claim.get("student_name", ""),
            "claimed_by_email": claim.get("student_email", ""),
            "claimed_by_roll_no": claim.get("roll_no", ""),
            "reason": "returned", "proof": proof,
            "return_date_time": f"{return_date} {return_time}",
            "archived_at": datetime.utcnow(),
            "created_at": item.get("created_at")
        })
    student_user = users_collection.find_one({"email": claim.get("student_email", "")})
    if student_user:
        create_notification(str(student_user["_id"]), "student",
            f"Your item '{claim.get('item_name', '')}' has been returned successfully!", "returned")
    create_notification(session["user_id"], "staff",
        f"You approved and returned '{claim.get('item_name', '')}' to {claim.get('student_name', '')}.", "claim_done")
    return redirect(url_for("staff.pending_claims"))


@staff_bp.route("/claim", methods=["GET", "POST"])
def claim():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("auth.login"))
    if request.method == "GET":
        item_id = request.args.get("item_id")
        if item_id:
            try:
                item = items_collection.find_one({"_id": ObjectId(item_id)})
                if item:
                    return render_template("claim.html", selected_item_id=str(item["_id"]),
                                           selected_item_name=item.get("name", ""))
            except Exception:
                pass
        return render_template("claim.html")
    # POST
    item_id = request.form.get("item_id")
    student_name = request.form.get("student_name")
    roll_no = request.form.get("roll_no")
    student_email = request.form.get("student_email")
    student_user = users_collection.find_one({"email": student_email})
    if not student_user:
        return "Student not found"
    proof = request.form.get("proof")
    return_date = request.form.get("return_date")
    return_time = request.form.get("return_time")
    if item_id:
        try:
            item_obj_id = ObjectId(item_id)
            items_collection.update_one({"_id": item_obj_id}, {"$set": {"status": "returned"}})
            item = items_collection.find_one({"_id": item_obj_id})
        except Exception:
            item = None
            
        if item:
            archived_items_collection.insert_one({
                "original_item_id": item["_id"], "name": item.get("name", ""),
                "category": item.get("category", ""), "type": item.get("type", ""),
                "date": item.get("date", ""), "location": item.get("location", ""),
                "description": item.get("description", ""),
                "image": item.get("image"), "image_content_type": item.get("image_content_type"),
                "image_filename": item.get("image_filename"), "image_id": item.get("image_id"),
                "reported_by": item.get("reported_by", ""),
                "claimed_by_name": student_name, "claimed_by_email": student_email,
                "claimed_by_roll_no": roll_no, "reason": "returned", "proof": proof,
                "return_date_time": f"{return_date} {return_time}",
                "archived_at": datetime.utcnow(),
                "created_at": item.get("created_at")
            })
            if student_user:
                create_notification(str(student_user["_id"]), "student",
                    f"Your item '{item.get('name', '')}' has been returned!", "returned")
    create_notification(session["user_id"], "staff",
        f"You manually returned an item to {student_name} ({roll_no}).", "claim_done")
    return redirect(url_for("staff.staff_dashboard"))


@staff_bp.route("/reject-claim/<claim_id>", methods=["POST"])
def reject_claim(claim_id):
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("auth.login"))
    try:
        claim_obj_id = ObjectId(claim_id)
    except Exception:
        from flask import flash
        flash("Invalid claim ID format.", "error")
        return redirect(url_for("staff.pending_claims"))
        
    claim = claims_collection.find_one({"_id": claim_obj_id})
    if not claim:
        from flask import flash
        flash("Claim not found.", "error")
        return redirect(url_for("staff.pending_claims"))
    reason = request.form.get("reason", "")
    is_false_claim = request.form.get("false_claim") == "on"
    claims_collection.update_one({"_id": ObjectId(claim_id)}, {"$set": {
        "status": "rejected", "processed_by": session["user_id"],
        "processed_at": datetime.utcnow(), "rejection_reason": reason
    }})
    if is_false_claim and reason:
        users_collection.update_one({"email": claim.get("student_email", "")},
            {"$set": {"account_flagged": True, "flag_reason": reason}})
    student_user = users_collection.find_one({"email": claim.get("student_email", "")})
    if student_user:
        msg = f"Your claim for '{claim.get('item_name', '')}' has been rejected."
        if reason:
            msg += f" Reason: {reason}"
        create_notification(str(student_user["_id"]), "student", msg,
            "account_flagged" if is_false_claim else "claim_rejected")
    return redirect(url_for("staff.pending_claims"))


@staff_bp.route("/previous-items")
def previous_items():
    if "user" not in session or session.get("role") != "staff":
        return redirect(url_for("auth.login"))
    items = list(archived_items_collection.find({}, ITEM_LIST_PROJECTION).sort("archived_at", -1).limit(50))
    return render_template("previous-items.html", items=items)
