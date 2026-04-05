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


import dataclasses
from typing import Optional, Any
from datetime import datetime
from bson.objectid import ObjectId

@dataclasses.dataclass
class Item:
    name: str
    category: str
    type: str # "lost" or "found"
    date: str
    location: str
    description: str
    status: str
    reported_by: str
    created_at: datetime
    dup_fingerprint: str = ""
    is_possible_duplicate: bool = False
    duplicate_of: Optional[ObjectId] = None
    image: Optional[Any] = None
    image_content_type: Optional[str] = None
    image_filename: Optional[str] = None

@dataclasses.dataclass
class Claim:
    item_id: ObjectId
    item_name: str
    item_description: str
    category: str
    location: str
    student_name: str
    student_email: str
    roll_no: str
    description_lost: str
    status: str
    requested_at: datetime
    requested_by: str
    processed_by: Optional[str] = None
    processed_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    proof: Optional[str] = None
    return_date: Optional[str] = None

def new_item(name: str, category: str, item_type: str, date: str, location: str, description: str,
             reported_by: str, dup_fingerprint: str = "", is_possible_duplicate: bool = False, 
             duplicate_of: Optional[ObjectId] = None, image_fields: dict = None) -> dict:
    """Return a new item document ready for insertion."""
    item = Item(
        name=name,
        category=category,
        type=item_type,
        date=date,
        location=location,
        description=description,
        status="active",
        reported_by=reported_by,
        created_at=datetime.utcnow(),
        dup_fingerprint=dup_fingerprint,
        is_possible_duplicate=is_possible_duplicate,
        duplicate_of=duplicate_of
    )
    doc = dataclasses.asdict(item)
    if image_fields:
        doc.update(image_fields)
    return doc

def new_claim(item_id: ObjectId, item: dict, student_name: str, student_email: str, roll_no: str,
              description_lost: str, requested_by: str) -> dict:
    """Return a new claim document ready for insertion."""
    claim = Claim(
        item_id=item_id,
        item_name=item.get("name", ""),
        item_description=item.get("description", ""),
        category=item.get("category", ""),
        location=item.get("location", ""),
        student_name=student_name,
        student_email=student_email,
        roll_no=roll_no,
        description_lost=description_lost,
        status="pending",
        requested_at=datetime.utcnow(),
        requested_by=requested_by
    )
    return dataclasses.asdict(claim)

