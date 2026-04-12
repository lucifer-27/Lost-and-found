import os
import sys

# To avoid importing app.extensions during test, we can try to mock things
# But let's just try to call the handle_console directly or see if we can import just the function

from app.services.email_service import send_otp_email

# Set environment
os.environ["EMAIL_PROVIDER"] = "console"
os.environ["TEST_EMAIL"] = "test@example.com"

print("Starting isolated console email test...")
success, msg = send_otp_email("test@example.com", "999888", "test")

if success:
    print("SUCCESS: Console mode works!")
else:
    print(f"FAILED: {msg}")
