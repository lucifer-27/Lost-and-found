import os
import smtplib
from email.mime.text import MIMEText


def send_otp_email(to_email, otp):
    sender_email = os.environ.get("EMAIL")
    sender_password = os.environ.get("EMAIL_PASS")

    if not sender_email or not sender_password:
        print("EMAIL CONFIG MISSING")
        return

    msg = MIMEText(f"Your OTP is: {otp}")
    msg["Subject"] = "CampusFind OTP"
    msg["From"] = sender_email
    msg["To"] = to_email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        print("OTP sent successfully ✅")
    except Exception as e:
        print("EMAIL ERROR:", e)
