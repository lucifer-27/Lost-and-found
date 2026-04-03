#!/usr/bin/env python3
"""
Email Testing Script for CampusFind
Run this to test email functionality in production
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_email_config():
    """Test email configuration"""
    print("🔍 Testing Email Configuration...\n")

    # Check Resend config
    resend_api_key = os.environ.get("RESEND_API_KEY", "").strip()
    resend_from_email = os.environ.get("RESEND_FROM_EMAIL", "").strip()

    print("📧 Resend Configuration:")
    print(f"  API Key: {'[SET]' if resend_api_key else '[MISSING]'}")
    print(f"  From Email: {resend_from_email if resend_from_email else '[MISSING]'}")

    # Check SMTP config
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    smtp_username = os.environ.get("SMTP_USERNAME", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "").strip()
    smtp_from_email = os.environ.get("SMTP_FROM_EMAIL", "").strip()

    print("\n📬 SMTP Configuration:")
    print(f"  Host: {smtp_host if smtp_host else '[MISSING]'}")
    print(f"  Username: {'[SET]' if smtp_username else '[MISSING]'}")
    print(f"  Password: {'[SET]' if smtp_password else '[MISSING]'}")
    print(f"  From Email: {smtp_from_email if smtp_from_email else '[MISSING]'}")

    # Test email sending
    print("\n🚀 Testing Email Sending...")
    try:
        from app.services.email_service import send_otp_email
        test_email = os.environ.get("TEST_EMAIL", "").strip()

        if not test_email:
            print("[ERROR] Set TEST_EMAIL environment variable to test email sending")
            return

        print(f"📤 Sending test OTP to: {test_email}")
        success = send_otp_email(test_email, "123456", "test")

        if success:
            print("[SUCCESS] Test email sent successfully!")
        else:
            print("[ERROR] Failed to send test email")

    except Exception as e:
        print(f"[ERROR] Error testing email: {str(e)}")

if __name__ == "__main__":
    test_email_config()