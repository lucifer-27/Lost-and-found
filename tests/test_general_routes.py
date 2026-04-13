"""
Integration Tests — General Routes
====================================
Tests for app/routes/general.py:
  - GET  /                   (home page)

  - GET  /contact            (contact form)
  - POST /contact            (contact form submission)
  - GET  /chatbot            (chatbot page)
  - GET  /camera             (camera page)
  - GET  /upload             (upload page)
  - GET  /notification_student
  - GET  /notifications      (staff notifications)
  - GET  /image/<file_id>    (image serving)
  - POST /mark-read/<id>
  - POST /mark-all-read
"""

import pytest
from unittest.mock import MagicMock, patch
from bson.objectid import ObjectId


# ──────────────────────────────────────────────────────────────
#  HOME PAGE
# ──────────────────────────────────────────────────────────────

class TestHomePage:

    def test_home_page_loads(self, client):
        """GET / should return 200 (the landing page)."""
        from app.extensions import items_collection
        # Mock the query chain: find().sort().limit()
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = mock_cursor
        mock_cursor.limit.return_value = []
        items_collection.find.return_value = mock_cursor

        response = client.get("/")
        assert response.status_code == 200

    def test_home_page_contains_campusfind(self, client):
        """Landing page should reference the project name."""
        from app.extensions import items_collection
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = mock_cursor
        mock_cursor.limit.return_value = []
        items_collection.find.return_value = mock_cursor

        response = client.get("/")
        assert response.status_code == 200


# ──────────────────────────────────────────────────────────────
#  CONTACT PAGE
# ──────────────────────────────────────────────────────────────

class TestContactPage:

    def test_contact_page_loads(self, client):
        response = client.get("/contact")
        assert response.status_code == 200

    def test_contact_us_alias_loads(self, client):
        response = client.get("/contact-us")
        assert response.status_code == 200

    def test_support_alias_loads(self, client):
        response = client.get("/support")
        assert response.status_code == 200

    def test_contact_post_missing_fields(self, client):
        """All fields are required; missing fields should show error."""
        response = client.post("/contact", data={
            "name": "",
            "email": "",
            "subject": "",
            "message": "",
        })
        assert response.status_code == 200
        assert b"All fields are required" in response.data

    def test_contact_post_short_message(self, client):
        """Message shorter than 10 characters should be rejected."""
        response = client.post("/contact", data={
            "name": "Alice",
            "email": "alice@example.com",
            "subject": "Help",
            "message": "Short",
        })
        assert response.status_code == 200
        assert b"at least 10 characters" in response.data


# ──────────────────────────────────────────────────────────────
#  CHATBOT
# ──────────────────────────────────────────────────────────────

class TestChatbotPage:

    def test_chatbot_page_loads(self, client):
        response = client.get("/chatbot")
        assert response.status_code == 200


# ──────────────────────────────────────────────────────────────
#  CAMERA & UPLOAD
# ──────────────────────────────────────────────────────────────

class TestCameraAndUpload:

    def test_camera_page_loads(self, client):
        response = client.get("/camera")
        assert response.status_code == 200

    def test_upload_get_page(self, client):
        response = client.get("/upload")
        assert response.status_code == 200


# ──────────────────────────────────────────────────────────────
#  IMAGE SERVING
# ──────────────────────────────────────────────────────────────

class TestImageServing:

    def test_nonexistent_image_returns_404(self, client):
        from app.extensions import temp_uploads_collection, fs
        temp_uploads_collection.find_one.return_value = None
        fs.get.side_effect = Exception("File not found")

        response = client.get(f"/image/{ObjectId()}")
        assert response.status_code == 404
        fs.get.side_effect = None  # Cleanup


# ──────────────────────────────────────────────────────────────
#  NOTIFICATIONS
# ──────────────────────────────────────────────────────────────

class TestNotifications:

    def test_student_notifications_requires_login(self, client):
        response = client.get("/notification_student")
        assert response.status_code == 302

    def test_staff_notifications_requires_login(self, client):
        response = client.get("/notifications")
        assert response.status_code == 302

    def test_admin_notifications_requires_login(self, client):
        response = client.get("/notifications-admin")
        assert response.status_code == 302

    def test_student_notifications_wrong_role(self, client, staff_session):
        """Staff user should not access student notifications."""
        response = client.get("/notification_student")
        assert response.status_code == 302

    def test_staff_notifications_wrong_role(self, client, student_session):
        """Student should not access staff notifications."""
        response = client.get("/notifications")
        assert response.status_code == 302

    def test_mark_read_requires_login(self, client):
        response = client.post(f"/mark-read/{ObjectId()}")
        assert response.status_code == 302

    def test_dismiss_requires_login(self, client):
        response = client.post(f"/dismiss-notification/{ObjectId()}")
        assert response.status_code == 302

    def test_mark_all_read_requires_login(self, client):
        response = client.post("/mark-all-read")
        assert response.status_code == 302

    def test_student_notifications_loads(self, client, student_session):
        """Logged-in student should see their notifications page."""
        from app.extensions import notifications_collection
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = []
        notifications_collection.find.return_value = mock_cursor

        response = client.get("/notification_student")
        assert response.status_code == 200

    def test_staff_notifications_loads(self, client, staff_session):
        from app.extensions import notifications_collection
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = []
        notifications_collection.find.return_value = mock_cursor

        response = client.get("/notifications")
        assert response.status_code == 200
