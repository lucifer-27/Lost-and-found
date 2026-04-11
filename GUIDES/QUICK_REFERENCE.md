# Email OTP System - Quick Reference Card

## 📋 Installation Checklist

### Phase 1: Dependencies ✅
- [x] Flask-Mail>=0.9.1 installed
- [x] Code files updated
- [x] Email service created

### Phase 2: Configuration (READ THIS!)
- [ ] Update .env with email credentials
- [ ] Test configuration: `python test_email_config.py`
- [ ] Verify test email arrives

### Phase 3: Testing  
- [ ] Test registration at /register
- [ ] Test login at /login
- [ ] Test forgot-password at /forgot-password
- [ ] Verify OTP emails arrive

---

## 🔧 Gmail Setup (5 minutes)

### Step 1: Enable 2FA
Go to: https://myaccount.google.com/security
- Click "2-Step Verification"  
- Enable it (need phone)

### Step 2: Get App Password
Go to: https://myaccount.google.com/apppasswords
- Select "Mail" and "Windows Computer"
- Click "Generate"
- Copy 16-character password

### Step 3: Update .env
```env
SEND_EMAIL_OTP=True
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_gmail@gmail.com
MAIL_PASSWORD=your_16_char_password
MAIL_DEFAULT_SENDER=noreply@lostandfound.com
```

### Step 4: Test
```bash
python test_email_config.py
```

Expected: ✅ ALL TESTS PASSED!

---

## 🚀 Launch Commands

```bash
# Install packages
pip install -r requirements.txt

# Test email config
python test_email_config.py

# Run app
python run.py

# Then visit:
# http://localhost:5000/register
# http://localhost:5000/login
# http://localhost:5000/forgot-password
```

---

## 📧 Test OTP Flows

### Registration
1. Go to: http://localhost:5000/register
2. Fill all fields
3. Submit
4. Check email for OTP
5. Enter OTP → Done!

### Login
1. Go to: http://localhost:5000/login
2. Enter email & password
3. Check email for OTP
4. Enter OTP → Logged in!

### Forgot Password
1. Go to: http://localhost:5000/forgot-password
2. Enter email
3. Check email for OTP
4. Enter OTP
5. Set new password → Done!

---

## ⚙️ Configuration Variables

| Variable | Value | Notes |
|----------|-------|-------|
| SEND_EMAIL_OTP | True/False | Enable email sending |
| OTP_EXPIRY_MINUTES | 10 | OTP validity period |
| OTP_MAX_ATTEMPTS | 5 | Wrong attempts allowed |
| OTP_RESEND_COOLDOWN_SECONDS | 60 | Wait before resend |

---

## 🐛 Troubleshooting

### "Connection refused"
- Check MAIL_SERVER: `smtp.gmail.com`
- Check MAIL_PORT: `587`
- Check internet connection

### "Authentication failed"  
- Most common: Wrong password
- Solution: Generate new App Password from Gmail
- Make sure 2FA is enabled

### "No module named 'flask_mail'"
- Solution: `pip install Flask-Mail`

### Emails not arriving
- Check spam folder
- Wait a few minutes
- Verify MAIL_USERNAME is correct

### Run tester for detailed debug:
```bash
python test_email_config.py
```

---

## 📂 Important Files

- **GUIDES/GMAIL_SETUP_GUIDE.md** - Gmail quick setup
- **GUIDES/EMAIL_OTP_SETUP.md** - Complete guide
- **GUIDES/IMPLEMENTATION_SUMMARY.md** - Full reference
- **test_email_config.py** - Configuration tester
- **app/services/email_service.py** - Email templates
- **.env.example** - Configuration template

---

## 📱 Email Features

- ✅ Professional HTML templates
- ✅ Responsive design (mobile/desktop)
- ✅ Different templates for each flow
- ✅ Security warnings in emails
- ✅ OTP expiry time shown
- ✅ Branded styling

---

## 🔐 Security Built-In

- ✅ OTP hashing (never plain text)
- ✅ OTP expiry (10 minutes default)
- ✅ Rate limiting (5 attempts max)
- ✅ Resend cooldown (60 seconds)
- ✅ Secure credentials (.env)

---

## ✨ What Your Users Get

Users can now:
- ✅ Register with email verification
- ✅ Login with 2FA (email OTP)
- ✅ Reset password with email verification

All with professional HTML emails and strong security!

---

## 🎯 Next Actions

1. **Read:** GUIDES/GMAIL_SETUP_GUIDE.md
2. **Setup:** Gmail App Password  
3. **Update:** .env file
4. **Test:** `python test_email_config.py`
5. **Run:** `python run.py`
6. **Verify:** Can register/login with OTP

---

**Status:** ✅ Ready to Deploy

All code is in place. Just need to:
1. Add Gmail credentials to .env
2. Run test script
3. Start your app!
