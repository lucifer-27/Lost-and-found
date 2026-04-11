"""
Item Model — defines the item document structure for MongoDB.
Since MongoDB is schemaless, this serves as documentation and
provides helper functions for item operations.
"""

from datetime import datetime

# Item document structure in MongoDB:
# {
#     "_id": ObjectId,
#     "name": str,               # item name
#     "category": str,           # e.g. "Electronics", "Clothing", etc.
#     "type": str,               # "lost" or "found"
#     "date": str,               # date lost/found (YYYY-MM-DD or with time)
#     "location": str,           # where item was lost/found
#     "description": str,        # detailed description
#     "status": str,             # "active" or "returned"
#     "reported_by": str,        # user_id of reporter
#     "created_at": datetime,    # when reported
#     "image": Binary,           # image data (optional)
#     "image_content_type": str, # e.g. "image/jpeg"
#     "image_filename": str,     # original filename
# }

# Archived Item document (same fields plus):
# {
#     "original_item_id": ObjectId,
#     "claimed_by_name": str,
#     "claimed_by_email": str,
#     "claimed_by_roll_no": str,
#     "reason": str,              # e.g. "returned"
#     "proof": str,
#     "return_date_time": str,
#     "archived_at": datetime,
# }

# Claim document structure:
# {
#     "_id": ObjectId,
#     "item_id": ObjectId,
#     "item_name": str,
#     "item_description": str,
#     "category": str,
#     "location": str,
#     "student_name": str,
#     "student_email": str,
#     "roll_no": str,
#     "description_lost": str,
#     "status": str,              # "pending", "approved", "rejected", "returned"
#     "requested_at": datetime,
#     "requested_by": str,        # user_id
#     "processed_by": str,        # staff user_id (optional)
#     "processed_at": datetime,   # (optional)
#     "rejection_reason": str,    # (optional)
#     "proof": str,               # (optional)
#     "return_date": str,         # (optional)
# }


def new_item(name, category, item_type, date, location, description,
             reported_by, image_fields=None):
    """Return a new item document ready for insertion."""
    doc = {
        "name": name,
        "category": category,
        "type": item_type,
        "date": date,
        "location": location,
        "description": description,
        "status": "active",
        "reported_by": reported_by,
        "created_at": datetime.utcnow(),
    }
    if image_fields:
        doc.update(image_fields)
    return doc


def new_claim(item_id, item, student_name, student_email, roll_no,
              description_lost, requested_by):
    """Return a new claim document ready for insertion."""
    return {
        "item_id": item_id,
        "item_name": item.get("name", ""),
        "item_description": item.get("description", ""),
        "category": item.get("category", ""),
        "location": item.get("location", ""),
        "student_name": student_name,
        "student_email": student_email,
        "roll_no": roll_no,
        "description_lost": description_lost,
        "status": "pending",
        "requested_at": datetime.utcnow(),
        "requested_by": requested_by,
    }
