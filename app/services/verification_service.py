import os
from math import ceil
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash
from .otp_service import generate_otp
from ..extensions import email_verifications_collection


def _otp_expiry_minutes():
    try:
        return max(1, int(os.environ.get("OTP_EXPIRY_MINUTES", "10")))
    except ValueError:
        return 10


def _otp_max_attempts():
    try:
        return max(1, int(os.environ.get("OTP_MAX_ATTEMPTS", "5")))
    except ValueError:
        return 5


def _otp_resend_cooldown_seconds():
    try:
        return max(0, int(os.environ.get("OTP_RESEND_COOLDOWN_SECONDS", "60")))
    except ValueError:
        return 60


def get_email_verification(email, purpose):
    return email_verifications_collection.find_one({"email": email, "purpose": purpose})


def get_resend_wait_seconds(email, purpose):
    record = get_email_verification(email, purpose)
    if not record:
        return 0
    resend_available_at = record.get("resend_available_at")
    if not resend_available_at:
        return 0
    remaining = (resend_available_at - datetime.utcnow()).total_seconds()
    return max(0, ceil(remaining))


def create_email_verification(email, purpose, payload=None):
    existing = get_email_verification(email, purpose)
    wait_seconds = get_resend_wait_seconds(email, purpose)
    if wait_seconds > 0:
        return None, f"Please wait {wait_seconds} seconds before requesting a new OTP."

    otp = generate_otp()
    now = datetime.utcnow()
    if payload is None and existing:
        payload = existing.get("payload") or {}
    email_verifications_collection.update_one(
        {"email": email, "purpose": purpose},
        {
            "$set": {
                "email": email,
                "purpose": purpose,
                "otp_hash": generate_password_hash(otp),
                "payload": payload or {},
                "attempt_count": 0,
                "created_at": now,
                "expires_at": now + timedelta(minutes=_otp_expiry_minutes()),
                "resend_available_at": now + timedelta(seconds=_otp_resend_cooldown_seconds()),
            }
        },
        upsert=True,
    )
    return otp, None


def clear_email_verification(email, purpose):
    email_verifications_collection.delete_one({"email": email, "purpose": purpose})


def verify_email_verification(email, purpose, otp):
    record = email_verifications_collection.find_one({"email": email, "purpose": purpose})
    if not record:
        return None, "No active verification request found. Please try again."

    if record.get("expires_at") and record["expires_at"] < datetime.utcnow():
        return None, "OTP expired. Please request a new code."

    attempt_count = int(record.get("attempt_count", 0))
    max_attempts = _otp_max_attempts()
    if attempt_count >= max_attempts:
        return None, "Too many invalid attempts. Please request a new OTP."

    if not check_password_hash(record.get("otp_hash", ""), otp):
        attempt_count += 1
        email_verifications_collection.update_one(
            {"_id": record["_id"]},
            {"$set": {"attempt_count": attempt_count}},
        )
        if attempt_count >= max_attempts:
            return None, "Too many invalid attempts. Please request a new OTP."
        remaining_attempts = max_attempts - attempt_count
        return None, f"Invalid OTP. {remaining_attempts} attempt(s) left."

    clear_email_verification(email, purpose)
    return record, None


def get_otp_expiry_minutes():
    return _otp_expiry_minutes()


def get_otp_max_attempts():
    return _otp_max_attempts()


def get_otp_resend_cooldown_seconds():
    return _otp_resend_cooldown_seconds()
