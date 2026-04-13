#!/usr/bin/env python3
"""
Email provider configuration tester for CampusFind.

This script validates the configured provider and can send a provider-level
test request without importing the Flask app.
"""

import importlib.util
import os
import sys
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent
EMAIL_SERVICE_PATH = PROJECT_ROOT / "app" / "services" / "email_service.py"


def load_email_service():
    spec = importlib.util.spec_from_file_location("campusfind_email_service", EMAIL_SERVICE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def first_env(*keys):
    for key in keys:
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return ""


def mask(value):
    value = (value or "").strip()
    if not value:
        return "NOT SET"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def print_check(label, ok, value, secret=False):
    status = "OK" if ok else "MISSING"
    display = mask(value) if secret else (value or "NOT SET")
    print(f"{label}: {status} ({display})")


def provider_requirements(provider):
    mapping = {
        "sendgrid": [("SENDGRID_API_KEY", True), ("MAIL_DEFAULT_SENDER", False)],
        "resend": [("RESEND_API_KEY", True), ("RESEND_FROM_EMAIL or MAIL_DEFAULT_SENDER", False)],
        "brevo": [("BREVO_API_KEY", True), ("BREVO_FROM_EMAIL or MAIL_DEFAULT_SENDER", False)],
        "smtp": [
            ("SMTP_HOST", False),
            ("SMTP_USERNAME or EMAIL", False),
            ("SMTP_PASSWORD or EMAIL_PASS", True),
            ("SMTP_FROM_EMAIL or MAIL_DEFAULT_SENDER", False),
        ],
    }
    return mapping.get(provider, [])


def get_requirement_value(name):
    if name == "RESEND_FROM_EMAIL or MAIL_DEFAULT_SENDER":
        return first_env("RESEND_FROM_EMAIL", "MAIL_DEFAULT_SENDER")
    if name == "BREVO_FROM_EMAIL or MAIL_DEFAULT_SENDER":
        return first_env("BREVO_FROM_EMAIL", "MAIL_DEFAULT_SENDER")
    if name == "SMTP_USERNAME or EMAIL":
        return first_env("SMTP_USERNAME", "EMAIL")
    if name == "SMTP_PASSWORD or EMAIL_PASS":
        return first_env("SMTP_PASSWORD", "EMAIL_PASS")
    if name == "SMTP_FROM_EMAIL or MAIL_DEFAULT_SENDER":
        return first_env("SMTP_FROM_EMAIL", "MAIL_DEFAULT_SENDER")
    return first_env(name)


def main():
    load_dotenv(dotenv_path=PROJECT_ROOT / ".env")
    email_service = load_email_service()
    provider = os.environ.get("EMAIL_PROVIDER", "auto").strip().lower() or "auto"

    print("=" * 60)
    print("CAMPUSFIND EMAIL CONFIGURATION CHECKER")
    print("=" * 60)
    print(f"EMAIL_PROVIDER: {provider}")
    print()

    readiness = {
        "sendgrid": email_service._has_sendgrid_config(),
        "resend": email_service._has_resend_config(),
        "brevo": email_service._has_brevo_config(),
        "smtp": email_service._has_smtp_config(),
    }

    for current_provider in ("sendgrid", "resend", "brevo", "smtp"):
        print(f"[{current_provider.upper()}]")
        for name, secret in provider_requirements(current_provider):
            value = get_requirement_value(name)
            print_check(name, bool(value), value, secret=secret)
        print(f"Ready: {'YES' if readiness[current_provider] else 'NO'}")
        print()

    if provider == "auto":
        available = [name for name, ready in readiness.items() if ready]
        if available:
            print(f"Auto mode can use: {', '.join(available)}")
        else:
            print("Auto mode has no configured provider available.")
    elif provider in {"debug", "console"}:
        print(f"{provider} mode is active, so no external provider is required.")
    elif provider in readiness:
        print(f"Configured provider ready: {'YES' if readiness[provider] else 'NO'}")
    else:
        print("Configured provider is not recognized by the current app.")

    print()
    test_email = os.environ.get("TEST_EMAIL", "").strip()
    if not test_email:
        print("Set TEST_EMAIL in .env to send a live test message.")
        return 0

    print(f"Sending live test email to: {test_email}")
    success, err = email_service.send_otp_email(test_email, "123456", "register")
    if success:
        print("Live email test passed.")
        return 0

    print(f"Live email test failed: {err}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
