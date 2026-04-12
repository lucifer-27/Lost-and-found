import os
from dotenv import load_dotenv
import sys

# Add current dir to sys.path to find app
sys.path.append(os.getcwd())

load_dotenv()

def check_env():
    print(f"EMAIL_PROVIDER: {os.environ.get('EMAIL_PROVIDER')}")
    print(f"SMTP_HOST: {os.environ.get('SMTP_HOST')}")
    print(f"SMTP_USERNAME: {os.environ.get('SMTP_USERNAME')}")
    print(f"SMTP_PASSWORD: {'SET' if os.environ.get('SMTP_PASSWORD') else 'MISSING'}")
    print(f"SMTP_FROM_EMAIL: {os.environ.get('SMTP_FROM_EMAIL')}")
    print(f"EMAIL: {os.environ.get('EMAIL')}")

    try:
        from app.services.email_service import _has_smtp_config, _smtp_settings
        print(f"HAS_SMTP_CONFIG: {_has_smtp_config()}")
        settings = _smtp_settings()
        print(f"SMTP_SETTINGS: {settings[0]}, {settings[1]}, {settings[2]}, {'SET' if settings[3] else 'MISSING'}, {settings[4]}")
    except Exception as e:
        print(f"ERROR: {str(e)}")

if __name__ == "__main__":
    check_env()
