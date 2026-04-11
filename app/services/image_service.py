import base64
from datetime import datetime
from bson.binary import Binary
from bson.objectid import ObjectId
from ..extensions import fs, temp_uploads_collection

DEFAULT_IMAGE_CONTENT_TYPE = "image/jpeg"


def normalize_image_content_type(content_type):
    if content_type and content_type.startswith("image/"):
        return content_type
    return DEFAULT_IMAGE_CONTENT_TYPE


def build_item_image_fields(image_bytes=None, content_type=None, filename=None):
    if not image_bytes:
        return {"image": None, "image_content_type": None, "image_filename": None}
    return {
        "image": Binary(image_bytes),
        "image_content_type": normalize_image_content_type(content_type),
        "image_filename": filename or None,
    }


def build_data_image_src(image_bytes, content_type):
    if not image_bytes:
        return None
    encoded = base64.b64encode(image_bytes).decode("ascii")
    return f"data:{normalize_image_content_type(content_type)};base64,{encoded}"


def extract_item_image_src(item):
    image_value = item.get("image")
    content_type = item.get("image_content_type") or DEFAULT_IMAGE_CONTENT_TYPE

    if isinstance(image_value, (bytes, bytearray, Binary)):
        return build_data_image_src(bytes(image_value), content_type)
    if isinstance(image_value, str):
        if image_value.startswith("data:image"):
            return image_value
        return f"data:{content_type};base64,{image_value}"

    legacy_image_id = item.get("image_id")
    if legacy_image_id:
        try:
            legacy_file = fs.get(legacy_image_id if isinstance(legacy_image_id, ObjectId) else ObjectId(legacy_image_id))
            return build_data_image_src(legacy_file.read(), getattr(legacy_file, "content_type", None))
        except Exception:
            return None
    return None


def store_temp_upload(image_bytes, content_type, filename=None):
    upload = {
        "image": Binary(image_bytes),
        "image_content_type": normalize_image_content_type(content_type),
        "image_filename": filename or None,
        "created_at": datetime.utcnow(),
    }
    return str(temp_uploads_collection.insert_one(upload).inserted_id)


def get_temp_upload(upload_id):
    if not upload_id:
        return None
    try:
        return temp_uploads_collection.find_one({"_id": ObjectId(upload_id)})
    except Exception:
        return None


def delete_temp_upload(upload_id):
    if not upload_id:
        return
    try:
        temp_uploads_collection.delete_one({"_id": ObjectId(upload_id)})
    except Exception:
        pass


def consume_temp_upload(upload_id):
    upload = get_temp_upload(upload_id)
    if not upload:
        return None, None, None
    delete_temp_upload(upload_id)
    return (
        bytes(upload.get("image") or b""),
        upload.get("image_content_type"),
        upload.get("image_filename"),
    )
