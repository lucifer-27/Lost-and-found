"""
Integration Tests — Admin Routes
==================================
Tests for app/routes/admin.py:
  - GET  /admin                        (admin dashboard)
  - GET  /admin/user/<user_id>         (user details)
  - GET  /admin/item/<item_id>         (item status)
  - GET  /admin/flagged-users          (flagged users list)
  - POST /admin/toggle-flag/<user_id>  (flag/unflag user)
  - GET  /admin/item-reports           (item reports)
  - POST /admin/item-reports/<id>/resolve (resolve report)
"""

import pytest
from unittest.mock import MagicMock, PropertyMock
from bson.objectid import ObjectId


# ──────────────────────────────────────────────────────────────
#  ADMIN DASHBOARD
# ──────────────────────────────────────────────────────────────

class TestAdminDashboard:

    def test_requires_login(self, client):
        response = client.get("/admin")
        assert response.status_code == 302

    def test_requires_admin_role(self, client, student_session):
        response = client.get("/admin")
        assert response.status_code == 302

    def test_requires_admin_role_not_staff(self, client, staff_session):
        response = client.get("/admin")
        assert response.status_code == 302

    def test_admin_can_access(self, client, admin_session):
        from app.extensions import (
            items_collection, archived_items_collection,
            claims_collection, users_collection,
        )
        # Mock all the aggregation queries
        items_collection.count_documents.return_value = 5
        archived_items_collection.count_documents.return_value = 2
        claims_collection.count_documents.return_value = 3

        # users query — find().sort() must return an iterable
        mock_users_cursor = MagicMock()
        mock_users_cursor.sort.return_value = iter([])
        users_collection.find.return_value = mock_users_cursor

        # items find for pending reports
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = mock_cursor
        mock_cursor.limit.return_value = iter([])
        items_collection.find.return_value = mock_cursor

        # archived items
        archived_items_collection.find.return_value = iter([])

        # claims with sort and limit
        mock_claims_cursor = MagicMock()
        mock_claims_cursor.sort.return_value = mock_claims_cursor
        mock_claims_cursor.limit.return_value = iter([])
        claims_collection.find.return_value = mock_claims_cursor

        response = client.get("/admin")
        assert response.status_code == 200


# ──────────────────────────────────────────────────────────────
#  ADMIN USER DETAILS
# ──────────────────────────────────────────────────────────────

class TestAdminUserDetails:

    def test_requires_login(self, client):
        response = client.get(f"/admin/user/{ObjectId()}")
        assert response.status_code == 302

    def test_requires_admin_role(self, client, student_session):
        response = client.get(f"/admin/user/{ObjectId()}")
        assert response.status_code == 302

    def test_nonexistent_user_redirects(self, client, admin_session):
        from app.extensions import users_collection
        users_collection.find_one.return_value = None

        response = client.get(f"/admin/user/{ObjectId()}")
        assert response.status_code == 302


# ──────────────────────────────────────────────────────────────
#  ADMIN ITEM STATUS
# ──────────────────────────────────────────────────────────────

class TestAdminItemStatus:

    def test_requires_login(self, client):
        response = client.get(f"/admin/item/{ObjectId()}")
        assert response.status_code == 302

    def test_requires_admin_role(self, client, staff_session):
        response = client.get(f"/admin/item/{ObjectId()}")
        assert response.status_code == 302

    def test_nonexistent_item_redirects(self, client, admin_session):
        from app.extensions import items_collection, archived_items_collection
        items_collection.find_one.return_value = None
        archived_items_collection.find_one.return_value = None

        response = client.get(f"/admin/item/{ObjectId()}")
        assert response.status_code == 302


# ──────────────────────────────────────────────────────────────
#  FLAGGED USERS
# ──────────────────────────────────────────────────────────────

class TestFlaggedUsers:

    def test_requires_login(self, client):
        response = client.get("/admin/flagged-users")
        assert response.status_code == 302

    def test_requires_admin_role(self, client, student_session):
        response = client.get("/admin/flagged-users")
        assert response.status_code == 302

    def test_admin_sees_flagged_users(self, client, admin_session):
        from app.extensions import users_collection
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = []
        users_collection.find.return_value = mock_cursor

        response = client.get("/admin/flagged-users")
        assert response.status_code == 200


# ──────────────────────────────────────────────────────────────
#  TOGGLE FLAG
# ──────────────────────────────────────────────────────────────

class TestToggleFlag:

    def test_requires_login(self, client):
        response = client.post(f"/admin/toggle-flag/{ObjectId()}")
        assert response.status_code == 302

    def test_requires_admin_role(self, client, student_session):
        response = client.post(f"/admin/toggle-flag/{ObjectId()}")
        assert response.status_code == 302

    def test_cannot_flag_admin_users(self, client, admin_session):
        from app.extensions import users_collection, notifications_collection
        target_id = ObjectId()
        users_collection.find_one.return_value = {
            "_id": target_id,
            "email": "admin2@sot.pdpu.ac.in",
            "role": "admin",
            "account_flagged": False,
        }

        response = client.post(f"/admin/toggle-flag/{target_id}")
        assert response.status_code == 302
        # Admin accounts should not be flaggable
        users_collection.update_one.assert_not_called()

    def test_flag_student(self, client, admin_session):
        from app.extensions import users_collection, notifications_collection
        target_id = ObjectId()
        users_collection.find_one.return_value = {
            "_id": target_id,
            "email": "24bcp002@sot.pdpu.ac.in",
            "role": "student",
            "account_flagged": False,
        }

        response = client.post(f"/admin/toggle-flag/{target_id}")
        assert response.status_code == 302
        users_collection.update_one.assert_called_once()


# ──────────────────────────────────────────────────────────────
#  ITEM REPORTS
# ──────────────────────────────────────────────────────────────

class TestItemReports:

    def test_requires_login(self, client):
        response = client.get("/admin/item-reports")
        assert response.status_code == 302

    def test_requires_admin_role(self, client, staff_session):
        response = client.get("/admin/item-reports")
        assert response.status_code == 302


# ──────────────────────────────────────────────────────────────
#  RESOLVE ITEM REPORT
# ──────────────────────────────────────────────────────────────

class TestResolveItemReport:

    def test_requires_login(self, client):
        response = client.post(f"/admin/item-reports/{ObjectId()}/resolve", data={
            "resolution_status": "dismissed",
        })
        assert response.status_code == 302

    def test_requires_admin_role(self, client, student_session):
        response = client.post(f"/admin/item-reports/{ObjectId()}/resolve", data={
            "resolution_status": "dismissed",
        })
        assert response.status_code == 302
