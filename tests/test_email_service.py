"""
Unit Tests — Email Service
===========================
Tests for app/services/email_service.py:
  - _build_otp_message()   — OTP email construction
  - _build_sender()        — sender string formatting
  - send_otp_email()       — provider routing (debug/console modes)
  - _has_resend_config()   — config detection
  - _has_brevo_config()    — config detection
  - _has_smtp_config()     — config detection
"""

import os
import pytest
from unittest.mock import patch
from app.services.email_service import (
    _build_otp_message,
    _build_sender,
    send_otp_email,
    _has_resend_config,
    _has_brevo_config,
    _has_smtp_config,
)


# ──────────────────────────────────────────────────────────────
#  _build_otp_message()
# ──────────────────────────────────────────────────────────────

class TestBuildOtpMessage:

    def test_register_purpose(self):
        subject, text, html = _build_otp_message("123456", "register")
        assert "Verify" in subject or "verify" in subject.lower()
        assert "123456" in text
        assert "123456" in html

    def test_login_purpose(self):
        subject, text, html = _build_otp_message("654321", "login")
        assert "login" in subject.lower()
        assert "654321" in text

    def test_reset_password_purpose(self):
        subject, text, html = _build_otp_message("111222", "reset_password")
        assert "Reset" in subject or "reset" in subject.lower()
        assert "111222" in text

    def test_unknown_purpose_falls_back(self):
        subject, text, html = _build_otp_message("999888", "unknown")
        assert "999888" in text
        assert subject  # Should still have a subject

    def test_html_contains_otp(self):
        _, _, html = _build_otp_message("456789", "register")
        assert "456789" in html

    def test_expiry_mentioned(self):
        _, text, _ = _build_otp_message("123456", "register")
        assert "10 minutes" in text or "expires" in text.lower()


# ──────────────────────────────────────────────────────────────
#  _build_sender()
# ──────────────────────────────────────────────────────────────

class TestBuildSender:

    def test_with_email(self):
        sender = _build_sender("noreply@campusfind.com")
        assert "noreply@campusfind.com" in sender
        assert "CampusFind" in sender or "<" in sender

    def test_with_empty_email(self):
        sender = _build_sender("")
        assert sender == ""

    def test_with_none_email(self):
        sender = _build_sender(None)
        assert sender == ""


# ──────────────────────────────────────────────────────────────
#  send_otp_email() — Debug Mode
# ──────────────────────────────────────────────────────────────

class TestSendOtpEmailDebugMode:
    """When EMAIL_PROVIDER=debug, OTP is just printed — no real email."""

    def test_debug_mode_returns_success(self):
        """Debug provider should return (True, None)."""
        # conftest.py sets EMAIL_PROVIDER=debug
        success, error = send_otp_email("test@sot.pdpu.ac.in", "123456")
        assert success is True
        assert error is None

    def test_debug_mode_with_different_purposes(self):
        for purpose in ("register", "login", "reset_password"):
            success, error = send_otp_email("t@sot.pdpu.ac.in", "000000", purpose)
            assert success is True

    @patch.dict(os.environ, {"EMAIL_PROVIDER": "console"})
    def test_console_mode_returns_success(self):
        """Console provider should return (True, '')."""
        success, error = send_otp_email("test@sot.pdpu.ac.in", "123456")
        assert success is True


# ──────────────────────────────────────────────────────────────
#  Config Detection
# ──────────────────────────────────────────────────────────────

class TestConfigDetection:

    @patch.dict(os.environ, {"RESEND_API_KEY": "", "RESEND_FROM_EMAIL": ""})
    def test_resend_not_configured(self):
        assert _has_resend_config() is False

    @patch.dict(os.environ, {"RESEND_API_KEY": "key123", "RESEND_FROM_EMAIL": "noreply@test.com"})
    def test_resend_configured(self):
        assert _has_resend_config() is True

    @patch.dict(os.environ, {"BREVO_API_KEY": "", "BREVO_FROM_EMAIL": ""})
    def test_brevo_not_configured(self):
        assert _has_brevo_config() is False

    @patch.dict(os.environ, {"BREVO_API_KEY": "key456", "BREVO_FROM_EMAIL": "noreply@test.com"})
    def test_brevo_configured(self):
        assert _has_brevo_config() is True

    @patch.dict(os.environ, {
        "SMTP_HOST": "", "SMTP_USERNAME": "", "SMTP_PASSWORD": "",
        "SMTP_FROM_EMAIL": "", "EMAIL": "", "EMAIL_PASS": "",
    })
    def test_smtp_not_configured(self):
        assert _has_smtp_config() is False
