from flask import Blueprint, render_template, redirect, url_for, session
from bson.objectid import ObjectId
from ..extensions import users_collection, claims_collection, archived_items_collection
from ..utils.helpers import ITEM_LIST_PROJECTION

student_bp = Blueprint("student", __name__)


@student_bp.route("/student")
def student_dashboard():
    if "user" not in session or session.get("role") != "student":
        return redirect(url_for("auth.login"))
    show_welcome = session.pop("first_login", False)
    report_success = session.pop("report_success", False)
    return render_template("student.html", show_welcome=show_welcome, report_success=report_success)


@student_bp.route("/student-history")
def student_history():
    if "user" not in session or session.get("role") != "student":
        return redirect(url_for("auth.login"))
    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    student_email = user["email"]
    student_claims = list(claims_collection.find({"requested_by": user_id}).sort("requested_at", -1))
    archived = list(archived_items_collection.find({"claimed_by_email": student_email}, ITEM_LIST_PROJECTION).sort("archived_at", -1))
    return render_template("student_history.html", claims=student_claims, archived_items=archived,
                           is_flagged=user.get("account_flagged", False), flag_reason=user.get("flag_reason", ""))
