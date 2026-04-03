import json
import os
import smtplib
from email.mime.text import MIMEText
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

RESEND_API_URL = "https://api.resend.com/emails"


def _build_sender(from_email):
    sender_name = os.environ.get("EMAIL_FROM_NAME", "CampusFind").strip() or "CampusFind"
    if not from_email:
        return ""
    return f"{sender_name} <{from_email}>"


def _smtp_settings():
    legacy_email = os.environ.get("EMAIL", "").strip()
    legacy_password = os.environ.get("EMAIL_PASS", "").strip()
    smtp_username = os.environ.get("SMTP_USERNAME", "").strip() or legacy_email
    smtp_password = os.environ.get("SMTP_PASSWORD", "").strip() or legacy_password
    from_email = os.environ.get("SMTP_FROM_EMAIL", "").strip() or legacy_email or smtp_username
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    if not smtp_host and legacy_email:
        smtp_host = "smtp.gmail.com"
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    return smtp_host, smtp_port, smtp_username, smtp_password, from_email


def _has_resend_config():
    return bool(os.environ.get("RESEND_API_KEY", "").strip() and os.environ.get("RESEND_FROM_EMAIL", "").strip())


def _has_smtp_config():
    smtp_host, _, smtp_username, smtp_password, from_email = _smtp_settings()
    return bool(smtp_host and smtp_username and smtp_password and from_email)


def _build_otp_message(otp, purpose):
    labels = {
        "register": ("Verify your CampusFind account", "Complete your registration"),
        "login": ("Your CampusFind login code", "Complete your login"),
        "reset_password": ("Reset your CampusFind password", "Reset your password"),
    }
    subject, heading = labels.get(purpose, ("Your CampusFind verification code", "Verify your email"))
    text = (
        f"{heading}\n\n"
        f"Your one-time code is: {otp}\n\n"
        "This code expires in 10 minutes. If you did not request this, you can ignore this email."
    )
    html = f"""
    <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #1f2937;">
        <h2 style="margin-bottom: 12px;">{heading}</h2>
        <p>Use this one-time code to continue:</p>
        <div style="font-size: 32px; font-weight: 700; letter-spacing: 8px; margin: 24px 0; color: #0d6efd;">
            {otp}
        </div>
        <p>This code expires in 10 minutes.</p>
        <p style="color: #6b7280;">If you did not request this, you can safely ignore this email.</p>
    </div>
    """
    return subject, text, html


def _send_via_resend(to_email, subject, text_body, html_body):
    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    from_email = os.environ.get("RESEND_FROM_EMAIL", "").strip()
    if not api_key or not from_email:
        print("RESEND CONFIG MISSING: RESEND_API_KEY or RESEND_FROM_EMAIL not set")
        return False

    payload = {
        "from": f"{os.environ.get('EMAIL_FROM_NAME', 'CampusFind')} <{from_email}>",
        "to": [to_email],
        "subject": subject,
        "text": text_body,
        "html": html_body,
    }

    try:
        import requests
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        response = requests.post("https://api.resend.com/emails", json=payload, headers=headers, timeout=15)

        if response.status_code in [200, 201]:
            print(f"✅ OTP email sent successfully via Resend to {to_email}")
            return True
        else:
            print(f"❌ RESEND ERROR: {response.status_code} - {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"❌ RESEND NETWORK ERROR: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ RESEND UNEXPECTED ERROR: {str(e)}")
        return False


def _send_via_smtp(to_email, subject, text_body):
    smtp_host, smtp_port, smtp_username, smtp_password, from_email = _smtp_settings()
    if not smtp_host or not smtp_username or not smtp_password or not from_email:
        print("SMTP CONFIG MISSING: Missing SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, or SMTP_FROM_EMAIL")
        return False

    msg = MIMEText(text_body)
    msg["Subject"] = subject
    msg["From"] = f"{os.environ.get('EMAIL_FROM_NAME', 'CampusFind')} <{from_email}>"
    msg["To"] = to_email

    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        print(f"✅ OTP email sent successfully via SMTP to {to_email}")
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ SMTP AUTH ERROR: {str(e)} - Check credentials")
        return False
    except smtplib.SMTPConnectError as e:
        print(f"❌ SMTP CONNECT ERROR: {str(e)} - Check SMTP host/port")
        return False
    except smtplib.SMTPException as e:
        print(f"❌ SMTP ERROR: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ SMTP UNEXPECTED ERROR: {str(e)}")
        return False


def send_otp_email(to_email, otp, purpose="verification"):
    subject, text_body, html_body = _build_otp_message(otp, purpose)
    provider = os.environ.get("EMAIL_PROVIDER", "auto").strip().lower()

    # Try Resend first (more reliable in production)
    if provider in ["auto", "resend"] and _has_resend_config():
        success = _send_via_resend(to_email, subject, text_body, html_body)
        if success:
            return True

    # Fallback to SMTP
    if provider in ["auto", "smtp"] and _has_smtp_config():
        success = _send_via_smtp(to_email, subject, text_body)
        if success:
            return True

    print("EMAIL CONFIG MISSING - No email provider configured")
    return False
