"""
Unit Tests — User Model & Item Model
=====================================
Tests for:
  - app/models/user_model.py  → new_user()
  - app/models/item_model.py  → new_item(), new_claim()

These are pure-function unit tests; they verify that factory
functions return documents with the correct fields, types, and
default values expected by MongoDB.
"""

import pytest
from datetime import datetime
from app.models.user_model import new_user
from app.models.item_model import new_item, new_claim


# ──────────────────────────────────────────────────────────────
#  USER MODEL TESTS
# ──────────────────────────────────────────────────────────────

class TestNewUser:
    """Tests for the new_user() factory function."""

    def test_returns_dict(self):
        """new_user() should return a dictionary."""
        user = new_user("Alice", "alice@sot.pdpu.ac.in", "student", "hashed_pw")
        assert isinstance(user, dict)

    def test_name_and_full_name_match(self):
        """Both 'name' and 'full_name' should hold the supplied name."""
        user = new_user("Bob Smith", "bob@sot.pdpu.ac.in", "staff", "h")
        assert user["name"] == "Bob Smith"
        assert user["full_name"] == "Bob Smith"

    def test_email_stored_correctly(self):
        user = new_user("Eve", "eve@sot.pdpu.ac.in", "student", "h")
        assert user["email"] == "eve@sot.pdpu.ac.in"

    def test_role_student(self):
        user = new_user("U", "u@sot.pdpu.ac.in", "student", "h")
        assert user["role"] == "student"

    def test_role_staff(self):
        user = new_user("U", "u@sot.pdpu.ac.in", "staff", "h")
        assert user["role"] == "staff"

    def test_role_admin(self):
        user = new_user("U", "u@sot.pdpu.ac.in", "admin", "h")
        assert user["role"] == "admin"

    def test_password_hash_stored(self):
        user = new_user("U", "u@sot.pdpu.ac.in", "student", "pbkdf2:sha256:xxx")
        assert user["password_hash"] == "pbkdf2:sha256:xxx"

    def test_not_flagged_by_default(self):
        """Newly created users must not be flagged."""
        user = new_user("U", "u@sot.pdpu.ac.in", "student", "h")
        assert user["account_flagged"] is False

    def test_required_keys_present(self):
        user = new_user("U", "u@sot.pdpu.ac.in", "student", "h")
        expected = {"name", "full_name", "email", "role",
                    "password_hash", "account_flagged"}
        assert set(user.keys()) == expected


# ──────────────────────────────────────────────────────────────
#  ITEM MODEL TESTS
# ──────────────────────────────────────────────────────────────

class TestNewItem:
    """Tests for the new_item() factory function."""

    def test_returns_dict(self):
        item = new_item("Laptop", "Electronics", "found",
                        "2026-01-15", "Library", "Black Dell", "uid1")
        assert isinstance(item, dict)

    def test_name_and_category(self):
        item = new_item("Phone", "Electronics", "lost",
                        "2026-02-01", "Cafeteria", "iPhone 15", "uid1")
        assert item["name"] == "Phone"
        assert item["category"] == "Electronics"

    def test_type_lost(self):
        item = new_item("Keys", "Keys", "lost",
                        "2026-01-01", "Parking", "Car keys", "uid1")
        assert item["type"] == "lost"

    def test_type_found(self):
        item = new_item("Keys", "Keys", "found",
                        "2026-01-01", "Parking", "Car keys", "uid1")
        assert item["type"] == "found"

    def test_default_status_is_active(self):
        item = new_item("Book", "Books & Stationery", "lost",
                        "2026-01-01", "Room 101", "Math textbook", "uid1")
        assert item["status"] == "active"

    def test_created_at_is_datetime(self):
        item = new_item("Bag", "Bags & Backpacks", "found",
                        "2026-01-01", "Gym", "Blue backpack", "uid1")
        assert isinstance(item["created_at"], datetime)

    def test_reported_by(self):
        item = new_item("Wallet", "Wallets & Purses", "found",
                        "2026-01-01", "Lab", "Brown wallet", "reporter_xyz")
        assert item["reported_by"] == "reporter_xyz"

    def test_without_image(self):
        """Item without image_fields should not contain image keys."""
        item = new_item("Watch", "Accessories", "lost",
                        "2026-01-01", "Sports", "Casio", "uid1")
        assert "image" not in item
        assert "image_content_type" not in item

    def test_with_image_fields(self):
        """Image fields should be merged into the document."""
        img = {
            "image": b"fake_bytes",
            "image_content_type": "image/png",
            "image_filename": "photo.png",
        }
        item = new_item("Watch", "Accessories", "lost",
                        "2026-01-01", "Sports", "Casio", "uid1",
                        image_fields=img)
        assert item["image"] == b"fake_bytes"
        assert item["image_content_type"] == "image/png"
        assert item["image_filename"] == "photo.png"

    def test_location_and_description(self):
        item = new_item("Bottle", "Water Bottles & Containers", "found",
                        "2026-03-10", "Block A", "Blue Nalgene", "uid1")
        assert item["location"] == "Block A"
        assert item["description"] == "Blue Nalgene"

    def test_date_stored_as_string(self):
        item = new_item("ID Card", "ID Cards & Documents", "lost",
                        "2026-04-01", "Admin Block", "PDPU ID", "uid1")
        assert item["date"] == "2026-04-01"


# ──────────────────────────────────────────────────────────────
#  CLAIM MODEL TESTS
# ──────────────────────────────────────────────────────────────

class TestNewClaim:
    """Tests for the new_claim() factory function."""

    _sample_item = {
        "name": "Phone",
        "description": "iPhone with blue case",
        "category": "Electronics",
        "location": "Library",
    }

    def test_returns_dict(self):
        claim = new_claim("item_id", self._sample_item, "Alice",
                          "alice@sot.pdpu.ac.in", "24bcp001",
                          "My phone has a scratch", "user_456")
        assert isinstance(claim, dict)

    def test_item_id(self):
        claim = new_claim("item_789", self._sample_item, "A",
                          "a@sot.pdpu.ac.in", "24bcp001", "desc", "u1")
        assert claim["item_id"] == "item_789"

    def test_student_details(self):
        claim = new_claim("id", self._sample_item, "Bob",
                          "bob@sot.pdpu.ac.in", "24bcp002", "desc", "u1")
        assert claim["student_name"] == "Bob"
        assert claim["student_email"] == "bob@sot.pdpu.ac.in"
        assert claim["roll_no"] == "24bcp002"

    def test_default_status_pending(self):
        claim = new_claim("id", self._sample_item, "A",
                          "a@sot.pdpu.ac.in", "24bcp001", "desc", "u1")
        assert claim["status"] == "pending"

    def test_requested_at_is_datetime(self):
        claim = new_claim("id", self._sample_item, "A",
                          "a@sot.pdpu.ac.in", "24bcp001", "desc", "u1")
        assert isinstance(claim["requested_at"], datetime)

    def test_copies_item_fields(self):
        claim = new_claim("id", self._sample_item, "A",
                          "a@sot.pdpu.ac.in", "24bcp001", "desc", "u1")
        assert claim["item_name"] == "Phone"
        assert claim["item_description"] == "iPhone with blue case"
        assert claim["category"] == "Electronics"
        assert claim["location"] == "Library"

    def test_missing_item_fields_default_to_empty_string(self):
        """Gracefully handle a sparse item dict."""
        claim = new_claim("id", {}, "A",
                          "a@sot.pdpu.ac.in", "24bcp001", "desc", "u1")
        assert claim["item_name"] == ""
        assert claim["item_description"] == ""

    def test_requested_by(self):
        claim = new_claim("id", self._sample_item, "A",
                          "a@sot.pdpu.ac.in", "24bcp001", "desc", "user_999")
        assert claim["requested_by"] == "user_999"

    def test_description_lost(self):
        claim = new_claim("id", self._sample_item, "A",
                          "a@sot.pdpu.ac.in", "24bcp001",
                          "Has a crack on the screen", "u1")
        assert claim["description_lost"] == "Has a crack on the screen"
