#!/usr/bin/env python3
"""
Email smoke test for CampusFind.

Checks the configured provider, reports which settings are present, and
sends a test OTP email when TEST_EMAIL is set.
"""

import importlib.util
import os
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


def mask(value):
    value = (value or "").strip()
    if not value:
        return "[MISSING]"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def first_env(*keys):
    for key in keys:
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return ""


def print_provider_status(label, configured, details):
    status = "READY" if configured else "MISSING"
    print(f"{label}: {status}")
    for name, value, secret in details:
        display = mask(value) if secret else (value or "[MISSING]")
        print(f"  {name}: {display}")
    print()


def main():
    load_dotenv(dotenv_path=PROJECT_ROOT / ".env")

    provider = os.environ.get("EMAIL_PROVIDER", "auto").strip().lower() or "auto"
    email_service = load_email_service()

    print("CampusFind Email Smoke Test")
    print("=" * 40)
    print(f"Configured provider: {provider}")
    print(f"From name: {os.environ.get('EMAIL_FROM_NAME', 'CampusFind')}")
    print()

    sendgrid_api_key = first_env("SENDGRID_API_KEY")
    default_sender = first_env("MAIL_DEFAULT_SENDER", "SENDGRID_FROM_EMAIL")
    resend_api_key = first_env("RESEND_API_KEY")
    resend_from_email = first_env("RESEND_FROM_EMAIL", "MAIL_DEFAULT_SENDER")
    brevo_api_key = first_env("BREVO_API_KEY")
    brevo_from_email = first_env("BREVO_FROM_EMAIL", "MAIL_DEFAULT_SENDER")
    smtp_host = first_env("SMTP_HOST")
    smtp_username = first_env("SMTP_USERNAME", "EMAIL")
    smtp_password = first_env("SMTP_PASSWORD", "EMAIL_PASS")
    smtp_from_email = first_env("SMTP_FROM_EMAIL", "MAIL_DEFAULT_SENDER", "EMAIL", "SMTP_USERNAME")

    print_provider_status(
        "SendGrid",
        email_service._has_sendgrid_config(),
        [
            ("SENDGRID_API_KEY", sendgrid_api_key, True),
            ("MAIL_DEFAULT_SENDER", default_sender, False),
        ],
    )
    print_provider_status(
        "Resend",
        email_service._has_resend_config(),
        [
            ("RESEND_API_KEY", resend_api_key, True),
            ("RESEND_FROM_EMAIL", resend_from_email, False),
        ],
    )
    print_provider_status(
        "Brevo",
        email_service._has_brevo_config(),
        [
            ("BREVO_API_KEY", brevo_api_key, True),
            ("BREVO_FROM_EMAIL", brevo_from_email, False),
        ],
    )
    print_provider_status(
        "SMTP",
        email_service._has_smtp_config(),
        [
            ("SMTP_HOST", smtp_host, False),
            ("SMTP_USERNAME", smtp_username, False),
            ("SMTP_PASSWORD", smtp_password, True),
            ("SMTP_FROM_EMAIL", smtp_from_email, False),
        ],
    )

    if provider in {"debug", "console"}:
        print(f"{provider} mode is active, so the app will not call an external email provider.")
        return

    test_email = os.environ.get("TEST_EMAIL", "").strip()
    if not test_email:
        print("Set TEST_EMAIL in .env to send a real test message.")
        return

    print(f"Sending test OTP to: {test_email}")
    success, err = email_service.send_otp_email(test_email, "123456", "register")

    if success:
        print("Email test completed successfully.")
    else:
        print(f"Email test failed: {err}")


if __name__ == "__main__":
    main()
