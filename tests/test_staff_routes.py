"""
Integration Tests — Staff Routes
==================================
Tests for app/routes/staff.py:
  - GET  /staff              (staff dashboard)
  - GET  /pending-claims     (pending claims list)
  - GET  /process-claim/<id> (process claim page)
  - POST /process-claim/<id> (approve & return)
  - POST /reject-claim/<id>  (reject a claim)
  - GET  /previous-items     (archived items)
  - GET  /claim              (manual claim form)
"""

import pytest
from unittest.mock import MagicMock
from bson.objectid import ObjectId


# ──────────────────────────────────────────────────────────────
#  STAFF DASHBOARD
# ──────────────────────────────────────────────────────────────

class TestStaffDashboard:

    def test_requires_login(self, client):
        response = client.get("/staff")
        assert response.status_code == 302

    def test_requires_staff_role(self, client, student_session):
        """Students should not access the staff dashboard."""
        response = client.get("/staff")
        assert response.status_code == 302

    def test_staff_can_access(self, client, staff_session):
        response = client.get("/staff")
        assert response.status_code == 200


# ──────────────────────────────────────────────────────────────
#  PENDING CLAIMS
# ──────────────────────────────────────────────────────────────

class TestPendingClaims:

    def test_requires_login(self, client):
        response = client.get("/pending-claims")
        assert response.status_code == 302

    def test_requires_staff_role(self, client, student_session):
        response = client.get("/pending-claims")
        assert response.status_code == 302

    def test_staff_sees_pending_claims(self, client, staff_session):
        from app.extensions import claims_collection
        claims_collection.find.return_value = []

        response = client.get("/pending-claims")
        assert response.status_code == 200


# ──────────────────────────────────────────────────────────────
#  PROCESS CLAIM
# ──────────────────────────────────────────────────────────────

class TestProcessClaim:

    def test_requires_login(self, client):
        response = client.get(f"/process-claim/{ObjectId()}")
        assert response.status_code == 302

    def test_nonexistent_claim_redirects(self, client, staff_session):
        from app.extensions import claims_collection
        claims_collection.find_one.return_value = None

        response = client.get(f"/process-claim/{ObjectId()}")
        assert response.status_code == 302

    def test_renders_claim_form(self, client, staff_session):
        from app.extensions import claims_collection
        claim_id = ObjectId()
        claims_collection.find_one.return_value = {
            "_id": claim_id,
            "item_id": ObjectId(),
            "item_name": "Test Phone",
            "student_name": "Alice",
            "student_email": "24bcp001@sot.pdpu.ac.in",
            "roll_no": "24bcp001",
            "description_lost": "My phone",
            "status": "pending",
        }

        response = client.get(f"/process-claim/{claim_id}")
        assert response.status_code == 200


# ──────────────────────────────────────────────────────────────
#  REJECT CLAIM
# ──────────────────────────────────────────────────────────────

class TestRejectClaim:

    def test_requires_login(self, client):
        response = client.post(f"/reject-claim/{ObjectId()}", data={
            "reason": "Not the owner",
        })
        assert response.status_code == 302

    def test_requires_staff_role(self, client, student_session):
        response = client.post(f"/reject-claim/{ObjectId()}", data={
            "reason": "Not the owner",
        })
        assert response.status_code == 302

    def test_nonexistent_claim_redirects(self, client, staff_session):
        from app.extensions import claims_collection
        claims_collection.find_one.return_value = None

        response = client.post(f"/reject-claim/{ObjectId()}", data={
            "reason": "Not the owner",
        })
        assert response.status_code == 302


# ──────────────────────────────────────────────────────────────
#  PREVIOUS ITEMS (ARCHIVED)
# ──────────────────────────────────────────────────────────────

class TestPreviousItems:

    def test_requires_login(self, client):
        response = client.get("/previous-items")
        assert response.status_code == 302

    def test_requires_staff_role(self, client, student_session):
        response = client.get("/previous-items")
        assert response.status_code == 302

    def test_staff_sees_previous_items(self, client, staff_session):
        from app.extensions import archived_items_collection
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = mock_cursor
        mock_cursor.limit.return_value = []
        archived_items_collection.find.return_value = mock_cursor

        response = client.get("/previous-items")
        assert response.status_code == 200


# ──────────────────────────────────────────────────────────────
#  MANUAL CLAIM FORM
# ──────────────────────────────────────────────────────────────

class TestManualClaim:

    def test_requires_login(self, client):
        response = client.get("/claim")
        assert response.status_code == 302

    def test_requires_staff_role(self, client, student_session):
        response = client.get("/claim")
        assert response.status_code == 302

    def test_staff_sees_claim_form(self, client, staff_session):
        response = client.get("/claim")
        assert response.status_code == 200
