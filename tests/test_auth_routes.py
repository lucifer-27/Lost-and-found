"""
Integration Tests — Authentication Routes
==========================================
Tests for app/routes/auth.py:
  - GET/POST  /register
  - GET/POST  /login
  - GET       /logout
  - GET/POST  /forgot-password
  - GET/POST  /verify-otp
  - POST      /resend-otp
  - GET/POST  /reset-password

These tests use the Flask test client and mock MongoDB collections.
CSRF protection and rate-limiting are disabled via conftest.py.
"""

import pytest
from unittest.mock import MagicMock, patch
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash


# ──────────────────────────────────────────────────────────────
#  REGISTRATION
# ──────────────────────────────────────────────────────────────

class TestRegister:

    def test_register_page_loads(self, client):
        """GET /register should return 200."""
        response = client.get("/register")
        assert response.status_code == 200

    def test_register_missing_full_name(self, client):
        """Submitting without a full name should show an error."""
        response = client.post("/register", data={
            "full_name": "",
            "email": "24bcp001@sot.pdpu.ac.in",
            "role": "student",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
        })
        assert response.status_code == 200
        assert b"Full name is required" in response.data

    def test_register_password_mismatch(self, client):
        response = client.post("/register", data={
            "full_name": "Alice",
            "email": "24bcp001@sot.pdpu.ac.in",
            "role": "student",
            "password": "Test@1234",
            "confirm_password": "Different@1234",
        })
        assert response.status_code == 200
        assert b"Passwords do not match" in response.data

    def test_register_invalid_email(self, client):
        """Email must be a valid college email ending with pdpu.ac.in."""
        response = client.post("/register", data={
            "full_name": "Alice",
            "email": "alice@gmail.com",
            "role": "student",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
        })
        assert response.status_code == 200
        assert b"college email" in response.data

    def test_register_weak_password(self, client):
        """Password must be 8+ chars with letters, numbers, special chars."""
        response = client.post("/register", data={
            "full_name": "Alice",
            "email": "24bcp001@sot.pdpu.ac.in",
            "role": "student",
            "password": "short",
            "confirm_password": "short",
        })
        assert response.status_code == 200
        assert b"Password must be" in response.data

    def test_register_duplicate_email(self, client):
        """An already-registered email should be rejected."""
        from app.extensions import users_collection
        users_collection.find_one.return_value = {"email": "24bcp001@sot.pdpu.ac.in"}

        response = client.post("/register", data={
            "full_name": "Alice",
            "email": "24bcp001@sot.pdpu.ac.in",
            "role": "student",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
        })
        assert response.status_code == 200
        assert b"already registered" in response.data

    def test_register_redirects_when_logged_in(self, client, student_session):
        """A logged-in user visiting /register should be redirected."""
        response = client.get("/register")
        assert response.status_code == 302

    def test_register_invalid_admin_code(self, client):
        """Admin registration with wrong code should fail."""
        from app.extensions import users_collection
        users_collection.find_one.return_value = None

        response = client.post("/register", data={
            "full_name": "Admin",
            "email": "24bcp099@sot.pdpu.ac.in",
            "role": "admin",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
            "admin_code": "wrong@999",
        })
        assert response.status_code == 200
        assert b"Invalid admin access code" in response.data


# ──────────────────────────────────────────────────────────────
#  LOGIN
# ──────────────────────────────────────────────────────────────

class TestLogin:

    def test_login_page_loads(self, client):
        response = client.get("/login")
        assert response.status_code == 200

    def test_login_invalid_credentials(self, client):
        from app.extensions import users_collection
        users_collection.find_one.return_value = None

        response = client.post("/login", data={
            "email": "wrong@sot.pdpu.ac.in",
            "role": "student",
            "password": "Wrong@12345",
        })
        assert response.status_code == 200
        assert b"Invalid email or password" in response.data

    def test_login_wrong_role(self, client):
        """Valid credentials but wrong role should fail."""
        from app.extensions import users_collection
        users_collection.find_one.return_value = {
            "_id": ObjectId(),
            "email": "24bcp001@sot.pdpu.ac.in",
            "role": "student",
            "password_hash": generate_password_hash("Test@1234"),
        }

        response = client.post("/login", data={
            "email": "24bcp001@sot.pdpu.ac.in",
            "role": "staff",  # Wrong role
            "password": "Test@1234",
        })
        assert response.status_code == 200
        assert b"Wrong role selected" in response.data

    def test_login_redirects_when_already_logged_in(self, client, student_session):
        response = client.get("/login")
        assert response.status_code == 302


# ──────────────────────────────────────────────────────────────
#  LOGOUT
# ──────────────────────────────────────────────────────────────

class TestLogout:

    def test_logout_clears_session(self, client, student_session):
        response = client.get("/logout")
        assert response.status_code == 302
        # After logout, session should be empty
        with client.session_transaction() as sess:
            assert "user" not in sess

    def test_logout_redirects_to_home(self, client, student_session):
        response = client.get("/logout")
        assert response.status_code == 302
        assert "/" in response.headers.get("Location", "")


# ──────────────────────────────────────────────────────────────
#  FORGOT PASSWORD
# ──────────────────────────────────────────────────────────────

class TestForgotPassword:

    def test_forgot_password_page_loads(self, client):
        response = client.get("/forgot-password")
        assert response.status_code == 200

    def test_forgot_password_unknown_email(self, client):
        from app.extensions import users_collection
        users_collection.find_one.return_value = None

        response = client.post("/forgot-password", data={
            "email": "unknown@sot.pdpu.ac.in",
        })
        assert response.status_code == 200
        assert b"Email not found" in response.data


# ──────────────────────────────────────────────────────────────
#  VERIFY OTP
# ──────────────────────────────────────────────────────────────

class TestVerifyOtp:

    def test_verify_otp_no_session_redirects(self, client):
        """Without verification_email in session, should redirect to login."""
        response = client.get("/verify-otp")
        assert response.status_code == 302

    def test_verify_otp_post_no_session_redirects(self, client):
        response = client.post("/verify-otp", data={"otp": "123456"})
        assert response.status_code == 302


# ──────────────────────────────────────────────────────────────
#  RESET PASSWORD
# ──────────────────────────────────────────────────────────────

class TestResetPassword:

    def test_reset_password_without_verification_redirects(self, client):
        """Without prior OTP verification, should redirect."""
        response = client.get("/reset-password")
        assert response.status_code == 302

    def test_reset_password_mismatch(self, client):
        """Passwords that don't match should show an error."""
        with client.session_transaction() as sess:
            sess["password_reset_verified_email"] = "test@sot.pdpu.ac.in"

        response = client.post("/reset-password", data={
            "password": "NewPass@1234",
            "confirm": "Different@1234",
        })
        assert response.status_code == 200
        assert b"Passwords do not match" in response.data

    def test_reset_password_weak(self, client):
        with client.session_transaction() as sess:
            sess["password_reset_verified_email"] = "test@sot.pdpu.ac.in"

        response = client.post("/reset-password", data={
            "password": "weak",
            "confirm": "weak",
        })
        assert response.status_code == 200
        assert b"Password must be" in response.data
