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
    print(f"  API Key: {'✅ Set' if resend_api_key else '❌ Missing'}")
    print(f"  From Email: {resend_from_email if resend_from_email else '❌ Missing'}")

    # Check SMTP config
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    smtp_username = os.environ.get("SMTP_USERNAME", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "").strip()
    smtp_from_email = os.environ.get("SMTP_FROM_EMAIL", "").strip()

    print("\n📬 SMTP Configuration:")
    print(f"  Host: {smtp_host if smtp_host else '❌ Missing'}")
    print(f"  Username: {'✅ Set' if smtp_username else '❌ Missing'}")
    print(f"  Password: {'✅ Set' if smtp_password else '❌ Missing'}")
    print(f"  From Email: {smtp_from_email if smtp_from_email else '❌ Missing'}")

    # Test email sending
    print("\n🚀 Testing Email Sending...")
    try:
        from app.services.email_service import send_otp_email
        test_email = os.environ.get("TEST_EMAIL", "").strip()

        if not test_email:
            print("❌ Set TEST_EMAIL environment variable to test email sending")
            return

        print(f"📤 Sending test OTP to: {test_email}")
        success = send_otp_email(test_email, "123456", "test")

        if success:
            print("✅ Test email sent successfully!")
        else:
            print("❌ Failed to send test email")

    except Exception as e:
        print(f"❌ Error testing email: {str(e)}")

if __name__ == "__main__":
    test_email_config()