"""
Unit Tests — Helper Utilities
===============================
Tests for app/utils/helpers.py:
  - get_user_display_fields()
  - parse_submitted_date()
  - _normalize_text()
  - build_duplicate_fingerprint()
  - build_claim_status_badge()
  - build_item_timeline()
  - create_notification()

Some helpers are pure functions; others rely on MongoDB
collections (mocked via conftest.py).
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock
from app.utils.helpers import (
    get_user_display_fields,
    parse_submitted_date,
    _normalize_text,
    build_duplicate_fingerprint,
    build_claim_status_badge,
    build_item_timeline,
    create_notification,
    categories,
    REPORT_CATEGORIES,
    REPORT_RESOLUTION_STATUSES,
)


# ──────────────────────────────────────────────────────────────
#  Constants
# ──────────────────────────────────────────────────────────────

class TestConstants:

    def test_categories_not_empty(self):
        assert len(categories) > 0

    def test_categories_contains_electronics(self):
        assert "Electronics" in categories

    def test_categories_contains_other(self):
        assert "Other" in categories

    def test_report_categories_not_empty(self):
        assert len(REPORT_CATEGORIES) > 0

    def test_report_resolution_statuses(self):
        assert "open" in REPORT_RESOLUTION_STATUSES
        assert "dismissed" in REPORT_RESOLUTION_STATUSES
        assert "actioned" in REPORT_RESOLUTION_STATUSES


# ──────────────────────────────────────────────────────────────
#  get_user_display_fields()
# ──────────────────────────────────────────────────────────────

class TestGetUserDisplayFields:

    def test_with_valid_user(self):
        user = {"name": "Alice", "email": "24bcp001@sot.pdpu.ac.in"}
        fields = get_user_display_fields(user)
        assert fields["name"] == "Alice"
        assert fields["roll_no"] == "24bcp001"
        assert fields["email"] == "24bcp001@sot.pdpu.ac.in"

    def test_with_full_name_fallback(self):
        user = {"full_name": "Bob Smith", "email": "bob@sot.pdpu.ac.in"}
        fields = get_user_display_fields(user)
        assert fields["name"] == "Bob Smith"

    def test_with_none_user(self):
        fields = get_user_display_fields(None)
        assert fields["name"] == "Unknown User"
        assert fields["roll_no"] == "--"
        assert fields["email"] == ""

    def test_email_without_at_sign(self):
        user = {"name": "Test", "email": "noatsign"}
        fields = get_user_display_fields(user)
        assert fields["roll_no"] == "noatsign"

    def test_empty_email(self):
        user = {"name": "Test", "email": ""}
        fields = get_user_display_fields(user)
        assert fields["roll_no"] == "--"


# ──────────────────────────────────────────────────────────────
#  parse_submitted_date()
# ──────────────────────────────────────────────────────────────

class TestParseSubmittedDate:

    def test_valid_date_string(self):
        result = parse_submitted_date("2026-04-10")
        assert result is not None
        assert result.year == 2026
        assert result.month == 4
        assert result.day == 10

    def test_invalid_date_string(self):
        assert parse_submitted_date("not-a-date") is None

    def test_none_input(self):
        assert parse_submitted_date(None) is None

    def test_empty_string(self):
        assert parse_submitted_date("") is None

    def test_wrong_format(self):
        assert parse_submitted_date("10/04/2026") is None

    def test_returns_date_object(self):
        from datetime import date
        result = parse_submitted_date("2026-01-01")
        assert isinstance(result, date)


# ──────────────────────────────────────────────────────────────
#  _normalize_text()
# ──────────────────────────────────────────────────────────────

class TestNormalizeText:

    def test_strips_and_lowercases(self):
        assert _normalize_text("  Hello World  ") == "hello world"

    def test_collapses_whitespace(self):
        assert _normalize_text("too   many    spaces") == "too many spaces"

    def test_none_returns_empty(self):
        assert _normalize_text(None) == ""

    def test_empty_string(self):
        assert _normalize_text("") == ""

    def test_numeric_input(self):
        assert _normalize_text(42) == "42"


# ──────────────────────────────────────────────────────────────
#  build_duplicate_fingerprint()
# ──────────────────────────────────────────────────────────────

class TestBuildDuplicateFingerprint:

    def test_basic_fingerprint(self):
        fp = build_duplicate_fingerprint(
            "Phone", "Electronics", "Library", "lost", "2026-01-01"
        )
        assert fp == "phone|electronics|library|lost|2026-01-01"

    def test_normalizes_whitespace(self):
        fp = build_duplicate_fingerprint(
            " My  Phone ", " Electronics ", "  Library  ", "found", "2026-01-01"
        )
        assert fp == "my phone|electronics|library|found|2026-01-01"

    def test_case_insensitive(self):
        fp1 = build_duplicate_fingerprint("LAPTOP", "ELECTRONICS", "LAB", "LOST", "2026-01-01")
        fp2 = build_duplicate_fingerprint("laptop", "electronics", "lab", "lost", "2026-01-01")
        assert fp1 == fp2

    def test_different_items_different_fingerprints(self):
        fp1 = build_duplicate_fingerprint("Phone", "Electronics", "Library", "lost", "2026-01-01")
        fp2 = build_duplicate_fingerprint("Laptop", "Electronics", "Lab", "found", "2026-01-02")
        assert fp1 != fp2


# ──────────────────────────────────────────────────────────────
#  build_claim_status_badge()
# ──────────────────────────────────────────────────────────────

class TestBuildClaimStatusBadge:

    def test_returned_status(self):
        badge = build_claim_status_badge("returned")
        assert badge["label"] == "Returned"
        assert "green" in badge["classes"]

    def test_approved_status(self):
        badge = build_claim_status_badge("approved")
        assert badge["label"] == "Approved"
        assert "blue" in badge["classes"]

    def test_rejected_status(self):
        badge = build_claim_status_badge("rejected")
        assert badge["label"] == "Rejected"
        assert "red" in badge["classes"]

    def test_pending_status(self):
        badge = build_claim_status_badge("pending")
        assert badge["label"] == "Pending"
        assert "amber" in badge["classes"]

    def test_unknown_status_defaults(self):
        badge = build_claim_status_badge("unknownstatus")
        assert badge["label"] == "No Claims"
        assert "gray" in badge["classes"]

    def test_none_status(self):
        badge = build_claim_status_badge(None)
        assert badge["label"] == "No Claims"

    def test_case_insensitive(self):
        badge = build_claim_status_badge("RETURNED")
        assert badge["label"] == "Returned"


# ──────────────────────────────────────────────────────────────
#  build_item_timeline()
# ──────────────────────────────────────────────────────────────

class TestBuildItemTimeline:

    def test_no_claims(self):
        item = {"type": "found", "created_at": datetime(2026, 1, 1)}
        steps = build_item_timeline(item, [])
        assert len(steps) == 5
        assert steps[0]["completed"] is True   # Reported Found
        assert steps[0]["name"] == "Reported Found"
        assert steps[1]["completed"] is False  # Claim Requested

    def test_lost_item_label(self):
        item = {"type": "lost", "created_at": datetime(2026, 1, 1)}
        steps = build_item_timeline(item, [])
        assert steps[0]["name"] == "Reported Lost"

    def test_with_pending_claim(self):
        item = {"type": "found", "created_at": datetime(2026, 1, 1)}
        claims = [{"status": "pending", "requested_at": datetime(2026, 1, 2)}]
        steps = build_item_timeline(item, claims)
        assert steps[1]["completed"] is True   # Claim Requested
        assert steps[2]["completed"] is False  # Not yet approved

    def test_with_approved_claim(self):
        item = {"type": "found", "created_at": datetime(2026, 1, 1)}
        claims = [{
            "status": "approved",
            "requested_at": datetime(2026, 1, 2),
            "processed_at": datetime(2026, 1, 3),
        }]
        steps = build_item_timeline(item, claims)
        assert steps[1]["completed"] is True  # Claim Requested
        assert steps[2]["completed"] is True  # Claim Approved
        assert steps[3]["completed"] is True  # Ready for Pickup

    def test_returned_item_all_steps_completed(self):
        item = {"type": "found", "created_at": datetime(2026, 1, 1),
                "status": "returned"}
        claims = [{
            "status": "returned",
            "requested_at": datetime(2026, 1, 2),
            "processed_at": datetime(2026, 1, 3),
        }]
        steps = build_item_timeline(item, claims)
        assert all(step["completed"] for step in steps)


# ──────────────────────────────────────────────────────────────
#  create_notification()
# ──────────────────────────────────────────────────────────────

class TestCreateNotification:

    def test_inserts_notification_document(self):
        from app.extensions import notifications_collection

        create_notification("user123", "student", "Test message", "general")

        notifications_collection.insert_one.assert_called_once()
        doc = notifications_collection.insert_one.call_args[0][0]
        assert doc["user_id"] == "user123"
        assert doc["role"] == "student"
        assert doc["message"] == "Test message"
        assert doc["type"] == "general"
        assert doc["read"] is False
        assert isinstance(doc["created_at"], datetime)

    def test_default_type_is_general(self):
        from app.extensions import notifications_collection

        create_notification("u1", "staff", "Hello")

        doc = notifications_collection.insert_one.call_args[0][0]
        assert doc["type"] == "general"
