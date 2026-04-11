#!/usr/bin/env python
"""
SendGrid Email Configuration Tester
Helps verify that SendGrid settings are correctly configured.
Run this script to test email sending before running the main app.
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_sendgrid_config():
    """Test SendGrid configuration"""
    
    print("=" * 60)
    print("SENDGRID EMAIL CONFIGURATION CHECKER")
    print("=" * 60)
    
    # Check environment variables
    print("\n📋 Configuration Check:")
    print("-" * 60)
    
    required_vars = [
        'SENDGRID_API_KEY',
        'MAIL_DEFAULT_SENDER'
    ]
    
    config = {}
    missing = []
    
    for var in required_vars:
        value = os.environ.get(var)
        if not value:
            missing.append(var)
            print(f"❌ {var}: NOT SET")
        else:
            # Mask sensitive info
            if 'KEY' in var or 'PASSWORD' in var:
                display_value = '*' * max(5, len(value) - 5) + value[-5:]
            else:
                display_value = value
            print(f"✅ {var}: {display_value}")
            config[var] = value
    
    if missing:
        print(f"\n⚠️  Missing configuration: {', '.join(missing)}")
        print("\nPlease set these in your .env file:")
        print("  SENDGRID_API_KEY=your_sendgrid_api_key")
        print("  MAIL_DEFAULT_SENDER=noreply@lostandfound.com")
        return False
    
    # Try importing SendGrid
    print("\n📦 Dependency Check:")
    print("-" * 60)
    
    try:
        from sendgrid import SendGridAPIClient
        print("✅ SendGrid: Installed")
    except ImportError:
        print("❌ SendGrid: NOT INSTALLED")
        print("\nInstall it with: pip install sendgrid")
        return False
    
    # Try creating Flask app with config
    print("\n🔧 Flask App Initialization:")
    print("-" * 60)
    
    try:
        from app import create_app
        app = create_app()
        print("✅ Flask app created successfully")
    except Exception as e:
        print(f"❌ Failed to create Flask app: {str(e)}")
        return False
    
    # Try sending test email
    print("\n📧 SendGrid Connection Test:")
    print("-" * 60)
    
    test_email = os.environ.get("MAIL_DEFAULT_SENDER", "")
    
    try:
        from sendgrid import SendGridAPIClient
        from sendgrid.helpers.mail import Mail, Email, To, Content
        
        api_key = os.environ.get("SENDGRID_API_KEY")
        sender_email = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@lostandfound.com")
        
        sg = SendGridAPIClient(api_key)
        
        # Create test email
        mail = Mail(
            from_email=Email(sender_email),
            to_emails=To(sender_email),
            subject="Lost & Found - SendGrid Configuration Test",
            html_content=Content("text/html", "If you received this email, your SendGrid configuration is working correctly!")
        )
        
        print(f"Sending test email to: {test_email}")
        response = sg.send(mail)
        
        if response.status_code in [200, 201, 202]:
            print("✅ Email sent successfully!")
        else:
            print(f"❌ SendGrid API error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Failed to send email: {str(e)}")
        print("\nCommon issues:")
        print("  - Invalid SENDGRID_API_KEY")
        print("  - API key doesn't have sending permissions")
        print("  - Sender email not verified in SendGrid")
        return False
    
    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED!")
    print("=" * 60)
    print("\nYour SendGrid configuration is ready for use!")
    print("Start your app with: python run.py")
    
    return True


if __name__ == "__main__":
    success = test_sendgrid_config()
    sys.exit(0 if success else 1)
