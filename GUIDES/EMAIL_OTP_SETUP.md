# Email OTP System Setup Guide

This guide walks you through setting up the Nodemailer-equivalent (Flask-Mail) email OTP system for your Lost & Found application.

## ✅ What's Been Done

The following changes have been automatically implemented:

1. ✅ Added `Flask-Mail>=0.9.1` to requirements.txt
2. ✅ Created `app/services/email_service.py` - Email sending service with HTML templates
3. ✅ Updated `app/config.py` - Email configuration support
4. ✅ Updated `app/extensions.py` - Initialized Flask-Mail
5. ✅ Updated `app/__init__.py` - Mail configuration in app factory
6. ✅ Updated `app/services/verification_service.py` - Integrated email sending
7. ✅ Updated `app/routes/auth.py` - Smart OTP display (dev vs production)

---

## 📋 Step-by-Step Setup

### **Step 1: Install Flask-Mail Package**

Run this command in your terminal from the project root:

```bash
pip install -r requirements.txt
```

Or install Flask-Mail directly:

```bash
pip install Flask-Mail
```

---

### **Step 2: Choose Your Email Provider**

Choose one of the following options:

#### **Option A: Gmail (Recommended for Easy Setup)**

1. Go to: https://myaccount.google.com/apppasswords
2. Select "Mail" and "Windows Computer"
3. Google will generate a 16-character app password
4. Copy this password

#### **Option B: Mailtrap (Free Testing)**

1. Go to: https://mailtrap.io/
2. Sign up for free account
3. Create a new inbox project
4. Get SMTP credentials from Settings tab

#### **Option C: SendGrid**

1. Go to: https://sendgrid.com/
2. Sign up for free account
3. Create API key
4. Email: apikey
5. Password: Your API key

#### **Option D: Other SMTP Providers**

- Mailgun
- AWS SES
- Yahoo Mail
- Outlook/Hotmail

---

### **Step 3: Update Your .env File**

Update or create your `.env` file with the following settings:

#### **For Gmail:**

```env
# Email Configuration
SEND_EMAIL_OTP=True
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_gmail@gmail.com
MAIL_PASSWORD=your_gmail_app_password
MAIL_DEFAULT_SENDER=noreply@lostandfound.com

# OTP Settings
OTP_EXPIRY_MINUTES=10
OTP_MAX_ATTEMPTS=5
OTP_RESEND_COOLDOWN_SECONDS=60
```

#### **For Mailtrap:**

```env
# Email Configuration
SEND_EMAIL_OTP=True
MAIL_SERVER=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USE_TLS=True
MAIL_USERNAME=your_mailtrap_username
MAIL_PASSWORD=your_mailtrap_password
MAIL_DEFAULT_SENDER=noreply@lostandfound.com

# OTP Settings
OTP_EXPIRY_MINUTES=10
OTP_MAX_ATTEMPTS=5
OTP_RESEND_COOLDOWN_SECONDS=60
```

#### **For SendGrid:**

```env
# Email Configuration
SEND_EMAIL_OTP=True
MAIL_SERVER=smtp.sendgrid.net
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=apikey
MAIL_PASSWORD=your_sendgrid_api_key
MAIL_DEFAULT_SENDER=noreply@lostandfound.com

# OTP Settings
OTP_EXPIRY_MINUTES=10
OTP_MAX_ATTEMPTS=5
OTP_RESEND_COOLDOWN_SECONDS=60
```

---

### **Step 4: Test the Email Configuration**

Create a test script to verify email sending works:

**File: `test_email_setup.py`**

```python
import os
from dotenv import load_dotenv
from app import create_app
from app.extensions import mail
from flask_mail import Message

# Load environment
load_dotenv()

# Create app context
app = create_app()

with app.app_context():
    try:
        # Create test email
        msg = Message(
            subject="Lost & Found - Email Test",
            recipients=["your_email@example.com"],  # CHANGE THIS
            body="If you see this, email configuration is working!"
        )
        
        # Send email
        mail.send(msg)
        print("✅ Email sent successfully!")
        
    except Exception as e:
        print(f"❌ Error sending email: {str(e)}")
        print("\nDebug Info:")
        print(f"- Mail Server: {app.config['MAIL_SERVER']}")
        print(f"- Mail Port: {app.config['MAIL_PORT']}")
        print(f"- Mail Username: {app.config['MAIL_USERNAME']}")
        print(f"- TLS Enabled: {app.config['MAIL_USE_TLS']}")
```

**Run the test:**

```bash
python test_email_setup.py
```

Expected output:
```
✅ Email sent successfully!
```

---

### **Step 5: Run the Application**

Start your Flask application:

```bash
python run.py
```

---

### **Step 6: Test the Complete OTP Flow**

#### **Test Registration with Email OTP**

1. Go to http://localhost:5000/register
2. Fill in registration form
3. You should see: "Check your email for the OTP code"
4. Check your email inbox for the OTP
5. Enter the OTP in the verification page
6. Registration should complete successfully

#### **Test Login with Email OTP**

1. Go to http://localhost:5000/login
2. Enter email and password
3. You should see: "Check your email for the OTP code"
4. Check your email for the OTP
5. Enter the OTP 
6. Should be redirected to your dashboard

#### **Test Forgot Password with Email OTP**

1. Go to http://localhost:5000/forgot-password
2. Enter your email
3. You should see: "Check your email for the OTP code"
4. Check your email for the OTP
5. Enter the OTP
6. You can now reset your password

---

## 🔒 Development vs Production

### **Development Mode (Email Disabled)**

If you want to test without actually sending emails:

```env
SEND_EMAIL_OTP=False
```

The system will display the OTP on screen with a "DEVELOPMENT MODE" message.

### **Production Mode (Email Enabled)**

When deploying to production:

```env
SEND_EMAIL_OTP=True
```

Emails will be sent to users only.

---

## 🐛 Troubleshooting

### **Error: "Connection refused"**

**Cause:** Mail server settings incorrect

**Fix:**
- Verify MAIL_SERVER and MAIL_PORT are correct
- Check your firewall isn't blocking port 587
- Ensure TLS is enabled if port is 587

### **Error: "Authentication failed"**

**Cause:** Username or password incorrect

**Fix:**
- Double-check `MAIL_USERNAME` and `MAIL_PASSWORD` in .env
- For Gmail, ensure you're using App Password, not your Gmail password
- Verify credentials work with manual SMTP test

### **Error: "No module named 'flask_mail'"**

**Cause:** Flask-Mail not installed

**Fix:**
```bash
pip install Flask-Mail
```

### **Error: "SSL: CERTIFICATE_VERIFY_FAILED"**

**Cause:** SSL/TLS certificate verification issue

**Fix:**
- Try disabling TLS temporarily: `MAIL_USE_TLS=False`
- Or use SSL with different port (usually 465 for SSL)

### **Emails Not Arriving**

**Check:**
1. Verify email was sent: Check application logs
2. Look in spam/junk folder
3. Check sender email address is in `MAIL_DEFAULT_SENDER`
4. For Gmail: Allow "Less secure apps" or use App Password

---

## 📧 Email Template Customization

Edit `app/services/email_service.py` to customize email templates:

- **OTP_LOGIN_TEMPLATE** - Login verification email
- **OTP_REGISTER_TEMPLATE** - Registration verification email
- **OTP_RESET_PASSWORD_TEMPLATE** - Password reset email

---

## ⏱️ OTP Configuration Options

In your `.env` file:

```env
# How long OTP is valid (in minutes)
OTP_EXPIRY_MINUTES=10

# How many attempts before locking user out
OTP_MAX_ATTEMPTS=5

# How long user must wait before requesting new OTP (in seconds)
OTP_RESEND_COOLDOWN_SECONDS=60
```

---

## 🎯 Summary

Your email OTP system is now ready! The flow is:

1. **User initiates action** (register/login/forgot password)
2. **OTP is generated** (6-digit random code)
3. **Email is sent** with the OTP (if `SEND_EMAIL_OTP=True`)
4. **User enters OTP** on verification page
5. **OTP is validated** and action completes

All configured automatically with proper error handling and security measures!

---

## 📞 Support

If you encounter issues:

1. Check the logs in the console where your Flask app is running
2. Verify all .env variables are correctly set
3. Try the `test_email_setup.py` script to isolate email issues
4. Check email provider's documentation for specific SMTP settings
