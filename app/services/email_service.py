"""Email service for sending OTP emails using SendGrid API."""

import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from ..config import SEND_EMAIL_OTP


# Email templates
OTP_LOGIN_TEMPLATE = """
<html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #2c3e50; text-align: center;">Lost & Found - Login Verification</h2>
            <p>Hi,</p>
            <p>You requested to login to your Lost & Found account. Please use the OTP below to verify your login:</p>
            
            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; text-align: center; margin: 20px 0;">
                <p style="font-size: 28px; font-weight: bold; color: #007bff; letter-spacing: 5px; margin: 0;">{{ otp }}</p>
            </div>
            
            <p><strong>This OTP will expire in {{ expiry_minutes }} minutes.</strong></p>
            
            <p style="color: #e74c3c;"><strong>⚠️ Important:</strong> Please don't share this OTP with anyone. Our staff will never ask for your OTP.</p>
            
            <p>If you didn't request this, please ignore this email.</p>
            
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
            <p style="font-size: 12px; color: #7f8c8d; text-align: center;">
                Lost & Found System<br>
                © 2024 All rights reserved
            </p>
        </div>
    </body>
</html>
"""

OTP_REGISTER_TEMPLATE = """
<html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #2c3e50; text-align: center;">Lost & Found - Email Verification</h2>
            <p>Welcome,</p>
            <p>We're excited to help you get started! Please verify your email address using the OTP below:</p>
            
            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; text-align: center; margin: 20px 0;">
                <p style="font-size: 28px; font-weight: bold; color: #28a745; letter-spacing: 5px; margin: 0;">{{ otp }}</p>
            </div>
            
            <p><strong>This OTP will expire in {{ expiry_minutes }} minutes.</strong></p>
            
            <p style="color: #e74c3c;"><strong>⚠️ Important:</strong> Please don't share this OTP with anyone. Our staff will never ask for your OTP.</p>
            
            <p>If you didn't create this account, please ignore this email.</p>
            
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
            <p style="font-size: 12px; color: #7f8c8d; text-align: center;">
                Lost & Found System<br>
                © 2024 All rights reserved
            </p>
        </div>
    </body>
</html>
"""

OTP_RESET_PASSWORD_TEMPLATE = """
<html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #2c3e50; text-align: center;">Lost & Found - Password Reset</h2>
            <p>Hi,</p>
            <p>We received a request to reset your password. Please use the OTP below to proceed with password reset:</p>
            
            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; text-align: center; margin: 20px 0;">
                <p style="font-size: 28px; font-weight: bold; color: #ff9800; letter-spacing: 5px; margin: 0;">{{ otp }}</p>
            </div>
            
            <p><strong>This OTP will expire in {{ expiry_minutes }} minutes.</strong></p>
            
            <p style="color: #e74c3c;"><strong>⚠️ Important:</strong> Please don't share this OTP with anyone. Our staff will never ask for your OTP.</p>
            
            <p>If you didn't request a password reset, please ignore this email and your password will remain unchanged.</p>
            
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
            <p style="font-size: 12px; color: #7f8c8d; text-align: center;">
                Lost & Found System<br>
                © 2024 All rights reserved
            </p>
        </div>
    </body>
</html>
"""


def send_otp_email(email, otp, purpose, expiry_minutes=10):
    """
    Send OTP email using SendGrid API.
    
    Args:
        email: User's email address
        otp: Generated OTP code
        purpose: Purpose of OTP ('login', 'register', or 'reset_password')
        expiry_minutes: OTP validity period in minutes
    
    Returns:
        tuple: (success: bool, message: str)
    """
    
    if not SEND_EMAIL_OTP:
        return True, "Email sending is disabled"
    
    if not email or not otp or not purpose:
        return False, "Missing required parameters"
    
    try:
        # Select template based on purpose
        templates = {
            "login": OTP_LOGIN_TEMPLATE,
            "register": OTP_REGISTER_TEMPLATE,
            "reset_password": OTP_RESET_PASSWORD_TEMPLATE,
        }
        
        template = templates.get(purpose, OTP_LOGIN_TEMPLATE)
        
        # Render template with OTP and expiry
        html_body = template.replace("{{ otp }}", otp).replace("{{ expiry_minutes }}", str(expiry_minutes))
        
        # Get SendGrid API key
        sendgrid_api_key = os.environ.get("SENDGRID_API_KEY", "").strip()
        if not sendgrid_api_key:
            return False, "SendGrid API key not configured"
        
        from ..config import MAIL_DEFAULT_SENDER
        
        # Create SendGrid client
        sg = SendGridAPIClient(sendgrid_api_key)
        
        # Create email
        mail = Mail(
            from_email=Email(MAIL_DEFAULT_SENDER),
            to_emails=To(email),
            subject=_get_email_subject(purpose),
            html_content=Content("text/html", html_body)
        )
        
        # Send email
        response = sg.send(mail)
        
        if response.status_code in [200, 201, 202]:
            return True, f"OTP sent successfully to {email}"
        else:
            return False, f"SendGrid API error: {response.status_code}"
    
    except Exception as e:
        error_msg = f"Failed to send email: {str(e)}"
        print(f"ERROR: {error_msg}")
        return False, error_msg


def _get_email_subject(purpose):
    """Get email subject based on purpose."""
    subjects = {
        "login": "Your Lost & Found Login OTP",
        "register": "Verify Your Email - Lost & Found",
        "reset_password": "Reset Your Lost & Found Password",
    }
    return subjects.get(purpose, "Lost & Found Verification")
