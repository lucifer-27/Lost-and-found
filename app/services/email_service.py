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


def _has_brevo_config():
    return bool(os.environ.get("BREVO_API_KEY", "").strip() and os.environ.get("BREVO_FROM_EMAIL", "").strip())


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
            print(f"[SUCCESS] OTP email sent successfully via Resend to {to_email}")
            return True, ""
        else:
            err = f"RESEND ERROR: {response.status_code} - {response.text}"
            print(f"[ERROR] {err}")
            return False, err

    except requests.exceptions.RequestException as e:
        err = f"RESEND NETWORK ERROR: {str(e)}"
        print(f"[ERROR] {err}")
        return False, err
    except Exception as e:
        err = f"RESEND UNEXPECTED ERROR: {str(e)}"
        print(f"[ERROR] {err}")
        return False, err


def _send_via_brevo(to_email, subject, text_body, html_body):
    api_key = os.environ.get("BREVO_API_KEY", "").strip()
    from_email = os.environ.get("BREVO_FROM_EMAIL", "").strip()
    if not api_key or not from_email:
        err = "BREVO CONFIG MISSING: BREVO_API_KEY or BREVO_FROM_EMAIL not set"
        print(err)
        return False, err

    sender_name = os.environ.get('EMAIL_FROM_NAME', 'CampusFind').strip()
    payload = {
        "sender": {"name": sender_name, "email": from_email},
        "to": [{"email": to_email}],
        "subject": subject,
        "textContent": text_body,
        "htmlContent": html_body,
    }

    try:
        import requests
        headers = {
            "api-key": api_key,
            "Content-Type": "application/json",
        }
        response = requests.post("https://api.brevo.com/v3/smtp/email", json=payload, headers=headers, timeout=15)

        if response.status_code in [200, 201]:
            print(f"[SUCCESS] OTP email sent successfully via Brevo to {to_email}")
            return True, ""
        else:
            err = f"BREVO ERROR: {response.status_code} - {response.text}"
            print(f"[ERROR] {err}")
            return False, err

    except requests.exceptions.RequestException as e:
        err = f"BREVO NETWORK ERROR: {str(e)}"
        print(f"[ERROR] {err}")
        return False, err
    except Exception as e:
        err = f"BREVO UNEXPECTED ERROR: {str(e)}"
        print(f"[ERROR] {err}")
        return False, err



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
        import socket
        # Resolve to IPv4 manually to prevent "Network is unreachable" errors on IPv6-prioritized systems
        # without patching the global socket module.
        try:
            addr_infos = socket.getaddrinfo(smtp_host, smtp_port, family=socket.AF_INET, type=socket.SOCK_STREAM)
            if addr_infos:
                resolved_ip = addr_infos[0][4][0]
                server = smtplib.SMTP(timeout=15)
                server.connect(resolved_ip, smtp_port)
                # Set host back to original hostname for STARTTLS certificate validation
                server.host = smtp_host
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        except Exception as e:
            print(f"[WARNING] IPv4 resolution failed for {smtp_host}: {e}. Falling back to default.")
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
    provider = os.environ.get("EMAIL_PROVIDER", "auto").strip().lower()

    if provider == "debug":
        print(f"[DEBUG MODE] OTP for {to_email}: {otp}")
        return True, None

    # Console Mode
    if provider == "console":
        print("\n" + "="*50)
        print(f"[CONSOLE MODE] OTP for {to_email}")
        print(f"Code: {otp}")
        print(f"Purpose: {purpose}")
        print("="*50 + "\n")
        return True, ""

    # Try Brevo
    if provider in ["auto", "brevo"]:
        if _has_brevo_config():
            success, error_msg = _send_via_brevo(to_email, subject, text_body, html_body)
            if success:
                return True, ""
            if provider == "brevo":
                return False, f"Brevo API Failed: {error_msg}"
            print(f"[WARNING] Brevo delivery failed: {error_msg}. Proceeding to fallback...")
        elif provider == "brevo":
            return False, "Brevo configuration is missing (BREVO_API_KEY/BREVO_FROM_EMAIL)."

    # Try Resend
    if provider in ["auto", "resend"]:
        if _has_resend_config():
            success, error_msg = _send_via_resend(to_email, subject, text_body, html_body)
            if success:
                return True, ""
            if provider == "resend":
                return False, f"Resend API Failed: {error_msg}"
            print(f"[WARNING] Resend delivery failed: {error_msg}. Attempting SMTP fallback...")
        elif provider == "resend":
            return False, "Resend configuration is missing (RESEND_API_KEY/RESEND_FROM_EMAIL)."

    # Fallback to SMTP 
    if _has_smtp_config():
        success, error_msg = _send_via_smtp(to_email, subject, text_body)
        if success:
            return True, ""
        return False, f"SMTP Delivery Failed: {error_msg}"

    # If we reached here, no provider worked
    if provider == "auto":
        msg = "EMAIL CONFIG MISSING - All providers (Brevo, Resend, SMTP) are unconfigured or failed."
    else:
        msg = f"EMAIL CONFIG MISSING - Provider '{provider}' is not configured or failed, and fallback failed."
    
    print(f"[ERROR] {msg}")
    return False, msg
