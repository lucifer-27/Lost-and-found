# Quick Fix Guide: Immediate Actions Required

## 🚨 STOP - Production Not Ready

This application is **UNSAFE for concurrent users** (more than 2-3 simultaneous). Do NOT deploy to production without implementing Phase 1 fixes.

---

## Phase 1: CRITICAL FIXES (24-48 Hours)

### 1. Fix Race Conditions (🔴 System Breaking)

#### A. Temp Upload TOCTOU Race - FIX IMMEDIATELY
**File:** `app/services/image_service.py` (line ~136)

**BEFORE (BROKEN):**
```python
def consume_temp_upload(upload_id):
    upload = get_temp_upload(upload_id)
    if not upload:
        return None, None, None
    delete_temp_upload(upload_id)  # Gap between check and delete!
    return bytes(upload.get("image") or b""), ...
```

**AFTER (FIXED):**
```python
def consume_temp_upload(upload_id):
    if not upload_id:
        return None, None, None
    try:
        # Atomic find-and-delete in single operation
        upload = temp_uploads_collection.find_one_and_delete(
            {"_id": ObjectId(upload_id)}
        )
        if not upload:
            return None, None, None
        return (
            bytes(upload.get("image") or b""),
            upload.get("image_content_type"),
            upload.get("image_filename"),
        )
    except Exception:
        return None, None, None
```

---

#### B. Duplicate Claims - FIX IMMEDIATELY
**File:** `app/routes/items.py` (line ~189)

**BEFORE (BROKEN):**
```python
existing = claims_collection.find_one({
    "item_id": item_object_id,
    "requested_by": session["user_id"],
    "status": "pending"
})

if existing:
    session["claim_error"] = "Already submitted..."
    return redirect(...)

try:
    claims_collection.insert_one(dict(claim_record))  # Still inserted despite check!
except DuplicateKeyError:
    session["claim_error"] = "Already submitted..."
    return redirect(...)
```

**AFTER (FIXED):**
```python
# Ensure unique index exists
# Run once in init_db():
claims_collection.create_index(
    [("requested_by", 1), ("item_id", 1)],
    unique=True,
    partialFilterExpression={"status": "pending"}
)

# In request_claim():
try:
    claims_collection.insert_one(dict(claim_record))
except DuplicateKeyError:
    session["claim_error"] = "You already submitted a claim for this item."
    return redirect(url_for("items.items_list"))
```

---

#### C. Item Status Consistency - FIX IMMEDIATELY
**File:** `app/routes/staff.py` (line ~30)

**BEFORE (BROKEN):**
```python
def _execute_process_claim(db_session=None):
    claims_collection.update_one(...)  # Update 1
    # CRASH HERE: item still "active"!
    items_collection.update_one(...)   # Update 2
    # Another crash: archive missing!
    archived_items_collection.insert_one(...)  # Update 3
```

**AFTER (FIXED):**
```python
from pymongo.errors import OperationFailure

try:
    with client.start_session() as session:
        with session.start_transaction():
            # All succeed or all fail - atomic
            claims_collection.update_one(
                {"_id": ObjectId(claim_id)},
                {"$set": {
                    "status": "returned",
                    "processed_by": session_obj["user_id"],
                    "processed_at": datetime.utcnow(),
                    "proof": proof,
                    "return_date": f"{return_date} {return_time}"
                }},
                session=session
            )
            
            returned_item = items_collection.find_one_and_update(
                {"_id": claim["item_id"]},
                {"$set": {"status": "returned"}},
                session=session,
                return_document=ReturnDocument.AFTER
            )
            
            if returned_item:
                archived_items_collection.insert_one({
                    "original_item_id": returned_item["_id"],
                    "name": returned_item.get("name", ""),
                    # ... other fields ...
                    "archived_at": datetime.utcnow(),
                }, session=session)
                
except OperationFailure as e:
    print(f"Transaction failed: {e}")
    flash("Failed to process claim. Please try again.", "error")
    return redirect(url_for("staff.pending_claims"))
```

---

### 2. Fix Hardcoded SECRET_KEY (🔴 Session Hijacking Risk)
**File:** `app/config.py` (line 6)

**BEFORE (BROKEN - VISIBLE IN GIT):**
```python
SECRET_KEY = os.environ.get('SECRET_KEY') or '84cf1ebd744816054ebfac040509bb429e51d33f4105be392b9a6c386f82f94c'
```

**AFTER (FIXED):**
```python
SECRET_KEY = os.environ.get('SECRET_KEY')

if not SECRET_KEY:
    raise ValueError(
        "CRITICAL: SECRET_KEY environment variable not set! "
        "Generate one: python -c 'import secrets; print(secrets.token_hex(32))'"
    )
```

**Then:**
1. Generate new key: `python -c "import secrets; print(secrets.token_hex(32))"`
2. Set in environment: `export SECRET_KEY=<generated-value>`
3. Remove from all git history: 
   ```bash
   git filter-branch --tree-filter 'grep -r "84cf1ebd" . && sed -i "s/84cf1ebd.*/REMOVED/g" app/config.py' -- --all
   git push --force
   ```

---

### 3. Fix Memory-Based Rate Limiter (🔴 Memory Exhaustion)
**File:** `app/__init__.py` (line 21)

**BEFORE (BROKEN - WILL CRASH):**
```python
app.config["RATELIMIT_STORAGE_URI"] = "memory://"
```

**AFTER (FIXED - Option A: Redis):**
```bash
# Install Redis
pip install redis

# Start Redis (or use managed service)
redis-server

# In app/__init__.py:
app.config["RATELIMIT_STORAGE_URI"] = "redis://localhost:6379"
```

**AFTER (FIXED - Option B: In-Process with Cleanup):**
```python
from functools import lru_cache
import random
import time

# Fallback if Redis unavailable
@app.before_request  
def cleanup_rate_limiter():
    """Clean up rate limiter to prevent memory leak"""
    if random.random() < 0.001:  # Every ~1000 requests
        try:
            # Access limiter's storage and clear old entries
            limiter.storage.clear()
            print("Rate limiter storage cleared")
        except Exception as e:
            print(f"Warning: Could not clean rate limiter: {e}")

app.config["RATELIMIT_STORAGE_URI"] = "memory://"
```

**RECOMMENDED: Use Redis (better for production)**

---

### 4. Fix Database Connection Pool (🔴 Connection Exhaustion)
**File:** `app/extensions.py` (line ~45)

**BEFORE (BROKEN - Default 50 connections):**
```python
def _connect_mongo(uri):
    client = MongoClient(
        uri,
        serverSelectionTimeoutMS=10000,
        connectTimeoutMS=10000,
        socketTimeoutMS=10000,
    )
```

**AFTER (FIXED - Explicit limits):**
```python
def _connect_mongo(uri):
    client = MongoClient(
        uri,
        serverSelectionTimeoutMS=10000,
        connectTimeoutMS=10000,
        socketTimeoutMS=10000,
        maxPoolSize=20,  # Max 20 connections
        minPoolSize=5,   # Keep minimum 5 warm
        maxIdleTimeMS=45000,  # Close idle after 45s
        waitQueueTimeoutMS=5000,  # Queue timeout 5s
    )
```

Also add connection validation:
```python
try:
    client.admin.command("ping")
except Exception as e:
    print(f"MongoDB connection failed: {e}")
    raise
```

---

### 5. Disable DEBUG Mode in Production (🔴 Remote Code Execution Risk)
**File:** `run.py` (line 9)

**BEFORE (BROKEN - Exposes debugger):**
```python
debug = os.environ.get("DEBUG", "False") == "True"
app.run(host="0.0.0.0", port=port, debug=debug)
```

**AFTER (FIXED - Use Gunicorn in production):**
```python
if __name__ == "__main__":
    env = os.environ.get("ENV", "development")
    
    if env == "production":
        print("ERROR: Production environment detected!")
        print("Use gunicorn to run: gunicorn -w 4 --bind 0.0.0.0:$PORT run:app")
        sys.exit(1)
    
    # Development only
    debug = os.environ.get("DEBUG", "False") == "True"
    app.run(host="127.0.0.1", port=port, debug=debug, use_reloader=False)
```

**Procfile (already correct):**
```
web: gunicorn -w 4 --workers-class=sync --bind 0.0.0.0:$PORT run:app
```

---

## Phase 2: HIGH Priority Fixes (1-2 Weeks)

### 6. Add Database Query Indexes
**File:** `app/extensions.py` - Enhance `init_db()` function

Add these indexes in `init_db()`:

```python
def init_db():
    try:
        # Existing indexes...
        temp_uploads_collection.create_index("created_at", expireAfterSeconds=3600)
        users_collection.create_index("email", unique=True)
        
        # ADD THESE:
        
        # Critical for admin dashboard queries
        items_collection.create_index([("status", 1)])
        items_collection.create_index([("reported_by", 1)])
        items_collection.create_index([("created_at", -1)])
        items_collection.create_index([("status", 1), ("created_at", -1)])
        
        # Critical for claim queries
        claims_collection.create_index([("status", 1)])
        claims_collection.create_index([("requested_by", 1)])
        claims_collection.create_index([("requested_at", -1)])
        claims_collection.create_index([("status", 1), ("requested_at", -1)])
        
        # Critical for archives
        archived_items_collection.create_index([("created_at", -1)])
        archived_items_collection.create_index([("claimed_by_email", 1)])
        
        # Critical for user role queries
        users_collection.create_index([("role", 1)])
        
        print("INFO: All database indexes initialized.")
    except Exception as e:
        print(f"WARNING: Index initialization failed: {e}")
```

---

### 7. Fix Email Threading (Bounded Thread Pool)
**File:** `app/routes/general.py` (line ~116)

**BEFORE (BROKEN - Unbounded threads):**
```python
import threading

threading.Thread(
    target=send_contact_email,
    kwargs={...},
    daemon=True
).start()
```

**AFTER (FIXED - Thread pool):**
```python
from concurrent.futures import ThreadPoolExecutor
import atexit

# Initialize at module level
email_executor = ThreadPoolExecutor(max_workers=3)

def cleanup_executor():
    """Cleanup on app shutdown"""
    email_executor.shutdown(wait=False)

atexit.register(cleanup_executor)

# In contact route - replace threading.Thread:
email_executor.submit(
    send_contact_email,
    to_email="campusfind.lnf@gmail.com",
    subject=email_subject,
    body=send_email_body
)

# No need for daemon threads now - executor handles lifecycle
```

---

### 8. Add Proper Exception Logging
**File:** Create `app/logging_config.py`

```python
import logging
import logging.handlers
import os

def setup_logging():
    """Configure application logging"""
    
    # Create logger
    logger = logging.getLogger("app")
    logger.setLevel(logging.DEBUG)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(os.getcwd(), "logs", "app.log"),
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    
    # Add handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger

# In app/__init__.py:
from app.logging_config import setup_logging
logger = setup_logging()
```

---

## Critical Configuration Variables (Environment)

Create `.env` file with:

```bash
# CRITICAL - Must be set
SECRET_KEY=<generate-with-secrets.token_hex(32)>
ENV=development  # or 'production'

# MongoDB
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/?retryWrites=true

# Optional Redis (recommended for production)
REDIS_URL=redis://localhost:6379

# Email (configure for real emails)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM_EMAIL=your-email@gmail.com

# Rate limiting
OTP_EXPIRY_MINUTES=10
OTP_MAX_ATTEMPTS=5
OTP_RESEND_COOLDOWN_SECONDS=60

# Admin/Staff codes (strong values!)
ADMIN_SECRET=<generate-strong-random-32-char-string>
STAFF_SECRET=<generate-strong-random-32-char-string>

# Debug (NEVER set to True in production!)
DEBUG=False
```

---

## Testing Concurrent Issues

### Test 1: Concurrent Claims
```bash
# Create test_concurrent.py
python test_concurrent.py
```

```python
import threading
import requests
from bson import ObjectId

ITEM_ID = "your_item_id"
CLAIMS_CREATED = 0
ERRORS = []

def submit_claim():
    global CLAIMS_CREATED
    try:
        response = requests.post(
            "http://localhost:5000/request-claim",
            data={"item_id": ITEM_ID, "student_name": "Test", "description_lost": "Test"},
            cookies={"session": "your_session_id"}
        )
        if response.status_code == 302:
            CLAIMS_CREATED += 1
    except Exception as e:
        ERRORS.append(str(e))

# Launch 10 concurrent threads
threads = [threading.Thread(target=submit_claim) for _ in range(10)]
for t in threads:
    t.start()
for t in threads:
    t.join()

print(f"Claims created: {CLAIMS_CREATED}")
print(f"Errors: {ERRORS}")
print("✓ PASS" if CLAIMS_CREATED == 1 else "✗ FAIL - Race condition detected!")
```

---

## Deployment Checklist

- [ ] All Phase 1 fixes implemented
- [ ] SECRET_KEY generated and set in environment
- [ ] DEBUG=False in production
- [ ] Redis/Memcached configured for rate limiting
- [ ] Database indexes created
- [ ] Logging configured
- [ ] HTTPS enforced (not just secure flag)
- [ ] CORS properly configured
- [ ] Rate limits appropriate
- [ ] Backup strategy in place
- [ ] Error monitoring configured (Sentry, etc.)
- [ ] Load testing performed (50+ concurrent users)

---

## Monitoring Setup Recommendation

```python
# Add to app/__init__.py
from flask_talisman import Talisman  # Security headers
from prometheus_flask_exporter import PrometheusMetrics  # Metrics

Talisman(app)  # Add security headers
metrics = PrometheusMetrics(app)  # Prometheus monitoring
```

---

**Status:** Critical - Implement immediately before production (Not safe for >10 user deployment now)  
**Estimated Time:** 
- Phase 1 (Critical): 24-48 hours
- Phase 2 (High): 1-2 weeks
- Full Hardening: 1 month
