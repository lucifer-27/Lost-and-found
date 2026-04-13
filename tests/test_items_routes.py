"""
Integration Tests — Item Routes
=================================
Tests for app/routes/items.py:
  - GET  /items              (items list)
  - GET  /item/<item_id>     (item details)
  - POST /request-claim      (submit a claim)
  - POST /report-item/<id>   (report an item)
  - GET  /report-lost        (report lost form)
  - POST /report-lost        (submit lost report)
  - GET  /report-found       (report found form)
  - POST /report-found       (submit found report)
  - GET  /api/items/staff    (staff JSON API)
"""

import pytest
from unittest.mock import MagicMock
from bson.objectid import ObjectId


# ──────────────────────────────────────────────────────────────
#  ITEMS LIST
# ──────────────────────────────────────────────────────────────

class TestItemsList:

    def test_requires_login(self, client):
        response = client.get("/items")
        assert response.status_code == 302

    def test_student_sees_active_items(self, client, student_session):
        from app.extensions import items_collection
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = mock_cursor
        mock_cursor.limit.return_value = []
        items_collection.find.return_value = mock_cursor

        response = client.get("/items")
        assert response.status_code == 200

    def test_staff_sees_all_items(self, client, staff_session):
        from app.extensions import items_collection, claims_collection
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = mock_cursor
        mock_cursor.limit.return_value = []
        items_collection.find.return_value = mock_cursor

        mock_claims_cursor = MagicMock()
        mock_claims_cursor.sort.return_value = []
        claims_collection.find.return_value = mock_claims_cursor

        response = client.get("/items")
        assert response.status_code == 200


# ──────────────────────────────────────────────────────────────
#  ITEM DETAILS
# ──────────────────────────────────────────────────────────────

class TestItemDetails:

    def test_requires_login(self, client):
        response = client.get(f"/item/{ObjectId()}")
        assert response.status_code == 302

    def test_nonexistent_item_redirects(self, client, student_session):
        from app.extensions import items_collection, archived_items_collection
        items_collection.find_one.return_value = None
        archived_items_collection.find_one.return_value = None

        response = client.get(f"/item/{ObjectId()}")
        assert response.status_code == 302


# ──────────────────────────────────────────────────────────────
#  REQUEST CLAIM
# ──────────────────────────────────────────────────────────────

class TestRequestClaim:

    def test_requires_login(self, client):
        response = client.post("/request-claim", data={"item_id": str(ObjectId())})
        assert response.status_code == 302

    def test_requires_student_role(self, client, staff_session):
        """Only students can request claims."""
        response = client.post("/request-claim", data={"item_id": str(ObjectId())})
        assert response.status_code == 302

    def test_missing_item_id_redirects(self, client, student_session):
        response = client.post("/request-claim", data={"item_id": ""})
        assert response.status_code == 302

    def test_missing_fields_shows_error(self, client, student_session):
        """Missing student_name or description_lost should error."""
        response = client.post("/request-claim", data={
            "item_id": str(ObjectId()),
            "student_name": "",
            "description_lost": "",
        })
        assert response.status_code == 302  # Redirects with session error

    def test_invalid_item_id_shows_error(self, client, student_session):
        response = client.post("/request-claim", data={
            "item_id": "not-a-valid-id",
            "student_name": "Alice",
            "description_lost": "My phone",
        })
        assert response.status_code == 302


# ──────────────────────────────────────────────────────────────
#  REPORT ITEM
# ──────────────────────────────────────────────────────────────

class TestReportItem:

    def test_requires_login(self, client):
        response = client.post(f"/report-item/{ObjectId()}", data={
            "reason": "spam",
            "category": "Other",
        })
        assert response.status_code == 302

    def test_missing_reason(self, client, student_session):
        """Report without a reason should show error."""
        response = client.post(f"/report-item/{ObjectId()}", data={
            "reason": "",
            "category": "Other",
        })
        assert response.status_code == 302


# ──────────────────────────────────────────────────────────────
#  REPORT LOST
# ──────────────────────────────────────────────────────────────

class TestReportLost:

    def test_requires_login(self, client):
        response = client.get("/report-lost")
        assert response.status_code == 302

    def test_form_loads_for_student(self, client, student_session):
        response = client.get("/report-lost")
        assert response.status_code == 200

    def test_invalid_date(self, client, student_session):
        response = client.post("/report-lost", data={
            "item_name": "Phone",
            "category": "Electronics",
            "date_lost": "invalid-date",
            "location": "Library",
            "description": "My phone",
        })
        assert response.status_code == 200
        assert b"valid lost date" in response.data

    def test_future_date_rejected(self, client, student_session):
        response = client.post("/report-lost", data={
            "item_name": "Phone",
            "category": "Electronics",
            "date_lost": "2099-01-01",
            "location": "Library",
            "description": "My phone",
        })
        assert response.status_code == 200
        assert b"cannot be in the future" in response.data


# ──────────────────────────────────────────────────────────────
#  REPORT FOUND
# ──────────────────────────────────────────────────────────────

class TestReportFound:

    def test_requires_login(self, client):
        response = client.get("/report-found")
        assert response.status_code == 302

    def test_form_loads_for_staff(self, client, staff_session):
        response = client.get("/report-found")
        assert response.status_code == 200

    def test_invalid_date(self, client, staff_session):
        response = client.post("/report-found", data={
            "item_name": "Laptop",
            "category": "Electronics",
            "date_found": "bad-date",
            "location": "Lab A",
            "description": "Silver laptop",
        })
        assert response.status_code == 200
        assert b"valid found date" in response.data

    def test_future_date_rejected(self, client, staff_session):
        response = client.post("/report-found", data={
            "item_name": "Laptop",
            "category": "Electronics",
            "date_found": "2099-12-31",
            "location": "Lab A",
            "description": "Silver laptop",
        })
        assert response.status_code == 200
        assert b"cannot be in the future" in response.data


# ──────────────────────────────────────────────────────────────
#  STAFF JSON API
# ──────────────────────────────────────────────────────────────

class TestApiItemsStaff:

    def test_requires_staff_login(self, client):
        response = client.get("/api/items/staff")
        assert response.status_code == 401

    def test_student_forbidden(self, client, student_session):
        response = client.get("/api/items/staff")
        assert response.status_code == 401

    def test_staff_gets_json(self, client, staff_session):
        from app.extensions import items_collection
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = mock_cursor
        mock_cursor.limit.return_value = []
        items_collection.find.return_value = mock_cursor

        response = client.get("/api/items/staff")
        assert response.status_code == 200
        data = response.get_json()
        assert "items" in data
        assert isinstance(data["items"], list)
