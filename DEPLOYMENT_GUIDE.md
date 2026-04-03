# CampusFind Deployment Guide for Render

## 🚀 Deploying to Render

### Step 1: Set Up Resend Email Service (FREE)

1. **Sign up for Resend**: https://resend.com
2. **Verify your domain** (recommended) or use their free tier
3. **Get your API key** from the dashboard
4. **Set the verified sender email**

### Step 2: Configure Render Environment Variables

In your Render dashboard, go to your service settings and add these environment variables:

#### Required Variables:
```
MONGO_DB_NAME=lost_found_db
MONGO_URI=your_mongodb_connection_string
MONGO_DNS_RESOLVERS=1.1.1.1,8.8.8.8
MONGO_DNS_TIMEOUT_SECONDS=5

# Email Configuration (PRIMARY)
EMAIL_PROVIDER=resend
EMAIL_FROM_NAME=CampusFind
RESEND_API_KEY=re_your_actual_api_key_here
RESEND_FROM_EMAIL=noreply@yourdomain.com

# Email Configuration (FALLBACK)
EMAIL=campusfind.lnf@gmail.com
EMAIL_PASS=your_gmail_app_password
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=campusfind.lnf@gmail.com
SMTP_PASSWORD=your_gmail_app_password
SMTP_FROM_EMAIL=campusfind.lnf@gmail.com

# OTP Configuration
OTP_RESEND_COOLDOWN_SECONDS=15
OTP_EXPIRY_MINUTES=10
OTP_MAX_ATTEMPTS=5

# Flask Secret Key (generate a random one)
SECRET_KEY=your_random_secret_key_here
```

### Step 3: Update Build Command

Make sure your Render build command is:
```bash
pip install -r requirements.txt
```

### Step 4: Update Start Command

Make sure your Render start command is:
```bash
gunicorn --bind 0.0.0.0:$PORT run:app
```

### Step 5: Test Email Functionality

After deployment, test email sending:

1. **Add a test email** to your environment variables:
   ```
   TEST_EMAIL=your.email@example.com
   ```

2. **Run the test script** in Render's shell:
   ```bash
   python test_email.py
   ```

3. **Check logs** for detailed error messages

## 🔧 Troubleshooting Email Issues

### Common Problems:

1. **"RESEND CONFIG MISSING"**
   - Check that `RESEND_API_KEY` and `RESEND_FROM_EMAIL` are set correctly

2. **"SMTP AUTH ERROR"**
   - Gmail might be blocking the connection
   - Try using Resend instead

3. **"Network timeout"**
   - Check if Render is blocking outbound connections
   - Use Resend (more reliable in cloud environments)

4. **Emails going to spam**
   - Use a verified domain with Resend
   - Add SPF/DKIM records

### Testing Checklist:

- [ ] Environment variables are set correctly
- [ ] Resend API key is valid
- [ ] Domain is verified (if using custom domain)
- [ ] Test email script runs without errors
- [ ] Check Render logs for detailed error messages

## 📧 Alternative Email Services

If Resend doesn't work, try these alternatives:

1. **SendGrid** (Free tier: 100 emails/day)
2. **Mailgun** (Free tier: 5,000 emails/month)
3. **Postmark** (Free tier: 100 emails/month)

## 🆘 Still Having Issues?

1. Check Render logs for detailed error messages
2. Run `python test_email.py` in Render shell
3. Verify all environment variables are set correctly
4. Try the fallback SMTP configuration

## 📞 Support

If you're still having issues, check:
- Render documentation: https://docs.render.com/
- Resend documentation: https://resend.com/docs
- CampusFind logs for detailed error messages