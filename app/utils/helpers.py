from datetime import datetime
from bson.objectid import ObjectId
from ..extensions import (
    users_collection, items_collection, archived_items_collection,
    claims_collection, notifications_collection,
)
from ..services.image_service import extract_item_image_src

# Constants
ITEM_LIST_PROJECTION = {"image": 0, "image_content_type": 0, "image_filename": 0}

categories = [
    "Electronics", "Clothing", "Wallets & Purses", "ID Cards & Documents",
    "Keys", "Books & Stationery", "Bags & Backpacks", "Accessories",
    "Water Bottles & Containers", "Other",
]


def create_notification(user_id, role, message, notif_type="general"):
    notifications_collection.insert_one({
        "user_id": str(user_id),
        "role": role,
        "message": message,
        "type": notif_type,
        "read": False,
        "created_at": datetime.utcnow()
    })


def get_user_display_fields(user_doc):
    if not user_doc:
        return {"name": "Unknown User", "roll_no": "--", "email": ""}
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
    except Exception:
        return users_collection.find_one({"_id": user_id})


def parse_submitted_date(date_value):
    if not date_value:
        return None
    try:
        return datetime.strptime(date_value, "%Y-%m-%d").date()
    except ValueError:
        return None


def build_claim_status_badge(status):
    normalized = (status or "").lower()
    badges = {
        "returned": {"label": "Returned", "classes": "bg-green-100 text-green-700"},
        "approved": {"label": "Approved", "classes": "bg-blue-100 text-blue-700"},
        "rejected": {"label": "Rejected", "classes": "bg-red-100 text-red-700"},
        "pending": {"label": "Pending", "classes": "bg-amber-100 text-amber-700"},
    }
    return badges.get(normalized, {"label": "No Claims", "classes": "bg-gray-100 text-gray-700"})


def build_item_timeline(item, claims):
    reported_label = "Reported Found" if item.get("type") == "found" else "Reported Lost"
    steps = [
        {"name": reported_label, "completed": True, "date": item.get("created_at")},
        {"name": "Claim Requested", "completed": False, "date": None},
        {"name": "Claim Approved", "completed": False, "date": None},
        {"name": "Ready for Pickup", "completed": False, "date": None},
        {"name": "Item Returned", "completed": False, "date": None},
    ]
    if claims:
        ordered = sorted(claims, key=lambda c: c.get("requested_at") or datetime.min)
        steps[1]["completed"] = True
        steps[1]["date"] = ordered[0].get("requested_at")
        final = next((c for c in claims if c.get("status") in ["approved", "returned"]), None)
        if final:
            t = final.get("processed_at")
            steps[2]["completed"] = steps[3]["completed"] = True
            steps[2]["date"] = steps[3]["date"] = t
            if item.get("status") == "returned":
                steps[4]["completed"] = True
                steps[4]["date"] = t
    return steps


def enrich_claim_records(claims):
    for claim in claims:
        try:
            student = users_collection.find_one({"_id": ObjectId(claim["requested_by"])}) if claim.get("requested_by") else None
            claim["student_email"] = student["email"] if student else claim.get("student_email", "Unknown")
        except Exception:
            claim["student_email"] = claim.get("student_email", "Unknown")
        claim["claim_badge"] = build_claim_status_badge(claim.get("status"))
        if claim.get("processed_by"):
            try:
                staff = users_collection.find_one({"_id": ObjectId(claim["processed_by"])})
                claim["staff_email"] = staff["email"] if staff else "Unknown Staff"
            except Exception:
                claim["staff_email"] = "Unknown Staff"
    return claims


def find_item_for_detail(item_id):
    try:
        oid = ObjectId(item_id)
    except Exception:
        return None, None
    item = items_collection.find_one({"_id": oid})
    if item:
        return item, item["_id"]
    arch = archived_items_collection.find_one({"_id": oid})
    if arch:
        return arch, arch.get("original_item_id") or arch["_id"]
    arch = archived_items_collection.find_one({"original_item_id": oid})
    if arch:
        return arch, arch.get("original_item_id") or arch["_id"]
    return None, None


def prepare_item_detail_context(item_id, role, user_id=None):
    item, claim_item_id = find_item_for_detail(item_id)
    if not item:
        return None
    reporter_fields = get_user_display_fields(find_user_by_id(item.get("reported_by")))
    item["reporter_name"] = reporter_fields["name"]
    item["reporter_roll_no"] = reporter_fields["roll_no"]
    item["reporter_email"] = reporter_fields["email"]
    item["image_src"] = extract_item_image_src(item)

    claims = []
    if claim_item_id:
        claims = list(claims_collection.find({"item_id": claim_item_id}).sort("requested_at", -1))
        claims = enrich_claim_records(claims)

    user_claim = None
    if role == "student" and user_id and claim_item_id:
        user_claim = next((c for c in claims if str(c.get("requested_by", "")) == str(user_id)), None)

    source = user_claim or (claims[0] if claims else None)
    cs = build_claim_status_badge(source.get("status") if source else None)
    item["claim_status_label"] = cs["label"]
    item["claim_status_classes"] = cs["classes"]
    item["date_label"] = "Found Date" if item.get("type") == "found" else "Lost Date"

    return {"item": item, "claims": claims, "user_claim": user_claim, "steps": build_item_timeline(item, claims)}
