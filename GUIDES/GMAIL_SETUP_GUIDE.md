# Gmail Email OTP Setup - Quick Guide

This is the easiest and most recommended way to set up email OTP for your Lost & Found application.

## 🎯 Why Gmail?

- ✅ Free
- ✅ Reliable
- ✅ Easy to set up with App Passwords
- ✅ Good for testing and production
- ✅ No credit card needed

## 📝 Step 1: Enable 2-Factor Authentication (if not already enabled)

1. Go to: https://myaccount.google.com/security
2. Scroll to "How you sign in to Google"
3. Click "2-Step Verification"
4. Follow the prompts to enable 2FA
5. Verify with your phone

## 🔑 Step 2: Generate Gmail App Password

**IMPORTANT:** Gmail App Passwords only work if 2-Factor Authentication is enabled!

1. Go to: https://myaccount.google.com/apppasswords
   - (You might need to log in again)
2. Select **"Mail"** from the first dropdown
3. Select **"Windows Computer"** (or your device) from the second dropdown
4. Click **Generate**
5. Google will show a 16-character password
6. **Copy this password** (you'll use it in .env)

Example: `abcd efgh ijkl mnop`

## 🔧 Step 3: Update Your .env File

Add or update these lines in your `.env` file:

```env
# Enable email OTP
SEND_EMAIL_OTP=True

# Gmail SMTP Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_gmail@gmail.com
MAIL_PASSWORD=abcd efgh ijkl mnop
MAIL_DEFAULT_SENDER=noreply@lostandfound.com

# OTP Settings (optional - these are defaults)
OTP_EXPIRY_MINUTES=10
OTP_MAX_ATTEMPTS=5
OTP_RESEND_COOLDOWN_SECONDS=60
```

Replace:
- `your_gmail@gmail.com` with your actual Gmail address
- `abcd efgh ijkl mnop` with the 16-character App Password you generated

## ✅ Step 4: Test Email Configuration

Run this to verify everything works:

```bash
python test_email_config.py
```

Expected output:
```
✅ Configuration Check: All variables set
✅ Flask-Mail: Installed
✅ Flask app created successfully
✅ Email sent successfully!

=============================
✅ ALL TESTS PASSED!
=============================
```

If you get an error, check the troubleshooting section below.

## 🚀 Step 5: Run Your Application

Start the Flask app:

```bash
python run.py
```

Then test the OTP flow:

1. Go to http://localhost:5000/register
2. Sign up with a test account
3. You should receive an OTP email from your Gmail
4. Enter the OTP to complete registration
5. Done! ✅

---

## 🐛 Troubleshooting

### "Authentication failed" or "Invalid credentials"

**Cause:** Wrong password or using Gmail password instead of App Password

**Fix:**
- Go back to https://myaccount.google.com/apppasswords
- Make sure 2-Factor Authentication is enabled
- Generate a NEW App Password
- Copy it exactly (including spaces)
- Update your .env file
- Remove any old passwords from .env

### "Connection refused" or "Connection timeout"

**Cause:** Gmail SMTP server not reachable

**Fix:**
- Ensure MAIL_SERVER is exactly: `smtp.gmail.com`
- Ensure MAIL_PORT is: `587`
- Check your internet connection
- Check firewall isn't blocking port 587

### "No module named 'flask_mail'"

**Cause:** Flask-Mail not installed

**Fix:**
```bash
pip install Flask-Mail
```

### Emails not arriving in inbox

**Check:**
1. Look in **Spam/Junk folder**
2. Verify **MAIL_USERNAME** is your Gmail address
3. Check **MAIL_DEFAULT_SENDER** is formatted correctly
4. Wait a few minutes (sometimes there's a delay)

### "SEND_EMAIL_OTP" setting errors

**Fix:**
Ensure your .env has exactly:
```env
SEND_EMAIL_OTP=True
```

(Not `true`, not `TRUE`, must be `True`)

---

## 📧 Testing OTP Emails

### Test Registration
1. Go to: http://localhost:5000/register
2. Fill form and submit
3. Check your Gmail inbox
4. Copy the OTP
5. Enter it to verify

### Test Login  
1. Go to: http://localhost:5000/login
2. Enter credentials and submit
3. Check Gmail for OTP
4. Enter OTP to complete login

### Test Forgot Password
1. Go to: http://localhost:5000/forgot-password
2. Enter your email
3. Check Gmail for OTP
4. Enter OTP and reset password

---

## 💡 Pro Tips

1. **Test with yourself first:** Use a Gmail account you have access to for testing

2. **Save the App Password:** The 16-character password is important - keep it safe in your .env

3. **Don't use your real Gmail password:** Always use the App Password from step 2

4. **Check spam folder:** Gmail sometimes marks test emails as spam initially

5. **For production:** Gmail works great for small to medium projects. For high volume, consider:
   - Sendgrid (100 free emails/day)
   - Mailgun (1000 free emails/month)
   - AWS SES (62,000 free emails/month)

---

## ✨ You're All Set!

Your Lost & Found app now has a working email OTP system for:
- ✅ User Registration
- ✅ User Login  
- ✅ Password Reset

All emails are sent via Gmail with professional HTML templates!
