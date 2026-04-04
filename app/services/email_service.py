import os
import smtplib
from email.mime.text import MIMEText

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
        print(f"[SUCCESS] OTP email sent successfully via SMTP to {to_email}")
        return True, ""
    except smtplib.SMTPAuthenticationError as e:
        err = f"SMTP AUTH ERROR: {str(e)} - Check credentials"
        print(f"[ERROR] {err}")
        return False, err
    except smtplib.SMTPConnectError as e:
        err = f"SMTP CONNECT ERROR: {str(e)} - Check SMTP host/port"
        print(f"[ERROR] {err}")
        return False, err
    except smtplib.SMTPException as e:
        err = f"SMTP ERROR: {str(e)}"
        print(f"[ERROR] {err}")
        return False, err
    except Exception as e:
        err = f"SMTP UNEXPECTED ERROR: {str(e)}"
        print(f"[ERROR] {err}")
        return False, err


def send_otp_email(to_email, otp, purpose="verification"):
    subject, text_body, html_body = _build_otp_message(otp, purpose)
    print(f"DEBUG OTP for {to_email}: {otp}")

    if _has_smtp_config():
        success, error_msg = _send_via_smtp(to_email, subject, text_body)
        if success:
            return True, ""
        return False, f"SMTP Delivery Failed: {error_msg}"

    msg = "EMAIL CONFIG MISSING - No email provider configured"
    print(msg)
    return False, msg
