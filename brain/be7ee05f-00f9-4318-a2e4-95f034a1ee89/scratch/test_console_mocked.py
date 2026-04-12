import os
import sys
from unittest.mock import MagicMock

# Mock pymongo before any imports
sys.modules['pymongo'] = MagicMock()
sys.modules['gridfs'] = MagicMock()
sys.modules['flask_limiter'] = MagicMock()
sys.modules['flask_limiter.util'] = MagicMock()

# Now we can import our stuff
# Set environment
os.environ["EMAIL_PROVIDER"] = "console"
os.environ["TEST_EMAIL"] = "test@example.com"

# Mock the mongo stuff in app.extensions explicitly if needed
import app.extensions
app.extensions.users_collection = MagicMock()
app.extensions.email_verifications_collection = MagicMock()

from app.services.email_service import send_otp_email

print("Starting FULLY isolated console email test...")
success, msg = send_otp_email("test@example.com", "999888", "test")

if success:
    print("SUCCESS: Console mode works!")
else:
    print(f"FAILED: {msg}")
