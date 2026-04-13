"""Debug: check exactly what bytes are in the MONGO_URI line of .env"""
import os

env_path = os.path.join(os.path.dirname(__file__), ".env")

with open(env_path, "rb") as f:
    content = f.read()

# Check for BOM
if content.startswith(b'\xef\xbb\xbf'):
    print("WARNING: .env file has a UTF-8 BOM!")
elif content.startswith(b'\xff\xfe') or content.startswith(b'\xfe\xff'):
    print("WARNING: .env file has a UTF-16 BOM!")
else:
    print("OK: No BOM detected")

# Find and inspect the MONGO_URI line
lines = content.split(b'\n')
for i, line in enumerate(lines):
    if b'MONGO_URI=' in line and not line.strip().startswith(b'#'):
        print(f"\nLine {i+1} raw bytes: {line!r}")
        print(f"Line {i+1} decoded:   {line.decode('utf-8', errors='replace').strip()}")
        
        # Extract password
        decoded = line.decode('utf-8', errors='replace').strip()
        if '://' in decoded and '@' in decoded:
            after_scheme = decoded.split('://', 1)[1]
            creds = after_scheme.split('@', 1)[0]
            if ':' in creds:
                user, pwd = creds.split(':', 1)
                print(f"\nUsername: '{user}'")
                print(f"Password: '{pwd}'")
                print(f"Password bytes: {pwd.encode('utf-8')!r}")
                print(f"Password len: {len(pwd)}")
                # Check for sneaky characters
                for j, ch in enumerate(pwd):
                    if not ch.isascii() or ch in (' ', '\t', '\r', '\n'):
                        print(f"  SUSPICIOUS char at index {j}: {ch!r} (ord={ord(ch)})")

print("\n--- Now checking what os.environ sees ---")
from dotenv import load_dotenv
load_dotenv(env_path, override=True)
env_uri = os.environ.get("MONGO_URI", "")
print(f"os.environ MONGO_URI: {env_uri}")
if '://' in env_uri and '@' in env_uri:
    after_scheme = env_uri.split('://', 1)[1]
    creds = after_scheme.split('@', 1)[0]
    if ':' in creds:
        user, pwd = creds.split(':', 1)
        print(f"Password from env: '{pwd}' (len={len(pwd)})")

print("\n--- Testing connection with override=True loaded URI ---")
from pymongo import MongoClient
try:
    client = MongoClient(env_uri.strip(), serverSelectionTimeoutMS=8000)
    client.admin.command('ping')
    print("SUCCESS")
except Exception as e:
    print(f"FAILED: {e}")
