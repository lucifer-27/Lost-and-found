# SendGrid Email OTP Setup - Quick Guide

You've successfully switched from Gmail SMTP to **SendGrid API**! This is more reliable for production.

## 📧 Why SendGrid?

- ✅ **100 free emails/day** (much better than Gmail's restrictions)
- ✅ **Reliable delivery**
- ✅ **No SMTP configuration** needed
- ✅ **Easy API integration**
- ✅ **Production-ready**

---

## 🔑 Step 1: Get SendGrid API Key

1. Go to: https://sendgrid.com/free
2. **Sign up** for a free account
   - Email
   - Password
   - Verify email
3. After login, go to: https://app.sendgrid.com/settings/api_keys
4. Click **"Create API Key"**
5. Name it: `Lost and Found OTP` (or anything you like)
6. Select permission: **Full Access**
7. Click **Create & Copy**
8. **Copy the API key** (looks like: `SG.AbCdEfGhIjKlMnOpQrStUvWxYz...`)

📌 **Important:** Keep this key safe! Don't share it or commit to git.

---

## 🔧 Step 2: Update Your .env File

Add/update these lines in `.env`:

```env
# Email Configuration - SendGrid
SEND_EMAIL_OTP=True
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=your_sendgrid_api_key_here
MAIL_DEFAULT_SENDER=noreply@lostandfound.com
```

Replace:
- `your_sendgrid_api_key_here` with your actual SendGrid API key from Step 1

❌ **Don't do this:**
```env
SENDGRID_API_KEY=SG.xxx  # Don't commit this to git!
```

✅ **Instead:**
- Use `.env` file (already in .gitignore)
- Or use environment variables in your hosting platform

---

## ✅ Step 3: Test Configuration

Run the test script:

```bash
python test_email_config.py
```

Expected output:
```
✅ Configuration Check: All variables set
✅ SendGrid: Installed
✅ Flask app created successfully
✅ Email sent successfully!

=============================
✅ ALL TESTS PASSED!
=============================
```

---

## 🚀 Step 4: Run Your Application

Start your Flask app:

```bash
python run.py
```

---

## 🧪 Step 5: Test OTP Flows

Test the complete OTP system:

### Register
1. Go to http://localhost:5000/register
2. Fill in the form
3. Submit
4. Check your email for OTP
5. Enter OTP to complete registration

### Login
1. Go to http://localhost:5000/login
2. Enter credentials
3. Check email for OTP
4. Enter OTP to login

### Forgot Password
1. Go to http://localhost:5000/forgot-password
2. Enter email
3. Check email for OTP
4. Enter OTP and reset password

---

## 📝 What Changed?

| Aspect | Gmail SMTP | SendGrid |
|--------|-----------|----------|
| **Method** | SMTP Port 587 | REST API |
| **Setup** | App Password | API Key |
| **Free Daily Limit** | 500 emails | 100 emails |
| **Reliability** | Good | Excellent |
| **For Production** | Limited | ✅ Recommended |

---

## 🐛 Troubleshooting

### "SendGrid API key not configured"
- Check `.env` has `SENDGRID_API_KEY`
- Verify API key is correct (starts with `SG.`)
- Restart your app after updating `.env`

### "Email not arriving"
- Check spam folder
- Verify `MAIL_DEFAULT_SENDER` is an email address
- Wait 2-3 minutes for delivery
- Check SendGrid dashboard for delivery logs

### "Invalid API key"
- Go to https://app.sendgrid.com/settings/api_keys
- Generate a new API key
- Make sure permission is **Full Access**
- Update your `.env` with the new key

### "Module sendgrid not found"
```bash
pip install sendgrid
```

---

## 📊 SendGrid Dashboard

After sending emails, you can monitor them:

1. Go to: https://app.sendgrid.com/mail_settings
2. View delivery stats
3. Check bounce rates
4. Monitor for issues

---

## 🎯 Summary

**Installation Steps:**
1. ✅ SendGrid library installed
2. ✅ Code updated to use SendGrid API
3. 📝 Get SendGrid API key from https://sendgrid.com/free
4. 📝 Add API key to `.env`
5. ✅ Run test: `python test_email_config.py`
6. ✅ Start app: `python run.py`
7. ✅ Test OTP flows

**Everything is ready!** Just need your SendGrid API key.

---

## ⏱️ Configuration Variables

In your `.env`:

```env
# Enable/disable email sending
SEND_EMAIL_OTP=True

# Email provider (currently: sendgrid)
EMAIL_PROVIDER=sendgrid

# Your SendGrid API key
SENDGRID_API_KEY=your_key_here

# From email address
MAIL_DEFAULT_SENDER=noreply@lostandfound.com
```

---

## 💡 Pro Tips

1. **Test in development** - Use your own email to test before going live
2. **Monitor deliverability** - Check SendGrid dashboard regularly
3. **Warm up IP** - SendGrid provides tools to gradually increase volume
4. **Scale up later** - If you exceed 100/day, upgrade to paid plan
5. **Use webhooks** - SendGrid can track bounces, clicks, etc. (advanced)

---

**Ready?** 
1. Get your SendGrid API key
2. Update `.env`
3. Run `python test_email_config.py`
4. Start your app!

Your Lost & Found app now has production-ready email! 🚀
