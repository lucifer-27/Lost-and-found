"""
Integration Tests — Student Routes
=====================================
Tests for app/routes/student.py:
  - GET  /student          (student dashboard)
  - GET  /student-history  (claims and returned-items history)
"""

import pytest
from unittest.mock import MagicMock
from bson.objectid import ObjectId


# ──────────────────────────────────────────────────────────────
#  STUDENT DASHBOARD
# ──────────────────────────────────────────────────────────────

class TestStudentDashboard:

    def test_requires_login(self, client):
        response = client.get("/student")
        assert response.status_code == 302

    def test_requires_student_role(self, client, staff_session):
        """Staff should not access the student dashboard."""
        response = client.get("/student")
        assert response.status_code == 302

    def test_admin_cannot_access(self, client, admin_session):
        response = client.get("/student")
        assert response.status_code == 302

    def test_student_can_access(self, client, student_session):
        response = client.get("/student")
        assert response.status_code == 200

    def test_first_login_welcome(self, client):
        """On first login, student should see a welcome indicator."""
        uid = str(ObjectId())
        with client.session_transaction() as sess:
            sess["user"] = "24bcp001@sot.pdpu.ac.in"
            sess["user_id"] = uid
            sess["role"] = "student"
            sess["first_login"] = True

        response = client.get("/student")
        assert response.status_code == 200


# ──────────────────────────────────────────────────────────────
#  STUDENT HISTORY
# ──────────────────────────────────────────────────────────────

class TestStudentHistory:

    def test_requires_login(self, client):
        response = client.get("/student-history")
        assert response.status_code == 302

    def test_requires_student_role(self, client, staff_session):
        response = client.get("/student-history")
        assert response.status_code == 302

    def test_student_can_view_history(self, client, student_session):
        from app.extensions import users_collection, claims_collection, archived_items_collection
        users_collection.find_one.return_value = {
            "_id": ObjectId(student_session["user_id"]),
            "email": student_session["email"],
            "account_flagged": False,
        }

        mock_claims_cursor = MagicMock()
        mock_claims_cursor.sort.return_value = []
        claims_collection.find.return_value = mock_claims_cursor

        mock_archived_cursor = MagicMock()
        mock_archived_cursor.sort.return_value = []
        archived_items_collection.find.return_value = mock_archived_cursor

        response = client.get("/student-history")
        assert response.status_code == 200

    def test_flagged_user_sees_flag_info(self, client, student_session):
        """A flagged student should still be able to view history."""
        from app.extensions import users_collection, claims_collection, archived_items_collection
        users_collection.find_one.return_value = {
            "_id": ObjectId(student_session["user_id"]),
            "email": student_session["email"],
            "account_flagged": True,
            "flag_reason": "Suspicious activity",
        }

        mock_claims_cursor = MagicMock()
        mock_claims_cursor.sort.return_value = []
        claims_collection.find.return_value = mock_claims_cursor

        mock_archived_cursor = MagicMock()
        mock_archived_cursor.sort.return_value = []
        archived_items_collection.find.return_value = mock_archived_cursor

        response = client.get("/student-history")
        assert response.status_code == 200
