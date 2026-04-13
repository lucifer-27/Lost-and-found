"""
Shared pytest fixtures for the CampusFind (Lost-and-Found) test suite.

This module:
  - Sets safe test environment variables (no live DB or email credentials).
  - Patches pymongo.MongoClient and gridfs.GridFS so that importing
    app.extensions never attempts a real MongoDB connection.
  - Provides Flask test-app and test-client fixtures.
  - Exposes convenience fixtures for simulating logged-in sessions
    (student / staff / admin).
"""

import os
import pytest
from unittest.mock import MagicMock, patch
from bson.objectid import ObjectId

# ═══════════════════════════════════════════════════════════════════
#  1. TEST ENVIRONMENT VARIABLES
#     Must be set BEFORE any app code is imported so that
#     app/config.py picks them up via os.environ / load_dotenv.
# ═══════════════════════════════════════════════════════════════════

os.environ["MONGO_URI"] = "mongodb://testuser:testpass@localhost:27017/testdb"
os.environ["MONGO_DB_NAME"] = "test_lost_found_db"
os.environ["SECRET_KEY"] = "test-secret-key-for-pytest"
os.environ["ENV"] = "development"
os.environ["EMAIL_PROVIDER"] = "debug"
os.environ["SHOW_OTP_ON_SCREEN"] = "true"
os.environ["ADMIN_SECRET"] = "admin@123"
os.environ["STAFF_SECRET"] = "staff@123"
os.environ["OTP_EXPIRY_MINUTES"] = "10"
os.environ["OTP_MAX_ATTEMPTS"] = "5"
os.environ["OTP_RESEND_COOLDOWN_SECONDS"] = "60"

# ═══════════════════════════════════════════════════════════════════
#  2. MOCK MONGODB & GRIDFS
#     Patches are started at module level — BEFORE any import of
#     app.extensions can trigger create_mongo_client().
# ═══════════════════════════════════════════════════════════════════

_mock_mongo_client = MagicMock(name="MockMongoClient")
_mock_mongo_client.admin.command.return_value = {"ok": 1}

_mock_db = MagicMock(name="MockDB")
_collections: dict[str, MagicMock] = {}


def _collection_factory(name):
    """Return a unique MagicMock for each MongoDB collection name."""
    if name not in _collections:
        _collections[name] = MagicMock(name=f"MockCollection_{name}")
    return _collections[name]


_mock_db.__getitem__ = MagicMock(side_effect=_collection_factory)
_mock_mongo_client.__getitem__ = MagicMock(return_value=_mock_db)

# Start patches globally (before any app import)
patch("pymongo.MongoClient", return_value=_mock_mongo_client).start()
patch("gridfs.GridFS", return_value=MagicMock(name="MockGridFS")).start()


# ═══════════════════════════════════════════════════════════════════
#  3. CORE FIXTURES
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture
def app():
    """Create a Flask application configured for testing."""
    from app import create_app
    application = create_app()
    application.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,       # Disable CSRF for test POSTs
        "RATELIMIT_ENABLED": False,       # Disable rate-limiter
        "RATELIMIT_STORAGE_URI": "memory://",
    })
    yield application


@pytest.fixture
def client(app):
    """Flask test client — CSRF and rate-limiting are disabled."""
    return app.test_client()


@pytest.fixture(autouse=True)
def _reset_all_mocks():
    """Reset every mock collection before each test for isolation."""
    for coll in _collections.values():
        coll.reset_mock()
    yield


# ═══════════════════════════════════════════════════════════════════
#  4. LOGGED-IN SESSION HELPERS
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture
def student_session(client):
    """Simulate a logged-in student and return session info dict."""
    uid = str(ObjectId())
    with client.session_transaction() as sess:
        sess["user"] = "24bcp001@sot.pdpu.ac.in"
        sess["user_id"] = uid
        sess["role"] = "student"
    return {"user_id": uid, "email": "24bcp001@sot.pdpu.ac.in", "role": "student"}


@pytest.fixture
def staff_session(client):
    """Simulate a logged-in staff member and return session info dict."""
    uid = str(ObjectId())
    with client.session_transaction() as sess:
        sess["user"] = "staff01@sot.pdpu.ac.in"
        sess["user_id"] = uid
        sess["role"] = "staff"
    return {"user_id": uid, "email": "staff01@sot.pdpu.ac.in", "role": "staff"}


@pytest.fixture
def admin_session(client):
    """Simulate a logged-in admin and return session info dict."""
    uid = str(ObjectId())
    with client.session_transaction() as sess:
        sess["user"] = "admin01@sot.pdpu.ac.in"
        sess["user_id"] = uid
        sess["role"] = "admin"
    return {"user_id": uid, "email": "admin01@sot.pdpu.ac.in", "role": "admin"}
