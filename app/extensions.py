import sys
import dns.resolver
from pymongo import MongoClient
from pymongo.errors import OperationFailure
from gridfs import GridFS
from .config import (
    build_mongo_uri_candidates,
    MONGO_URI,
    MONGO_DIRECT_URI,
    MONGO_DB_NAME,
    MONGO_DNS_RESOLVERS,
    MONGO_DNS_TIMEOUT_SECONDS,
    redact_mongo_uri,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
)


def _configure_srv_dns_resolver():
    if not MONGO_URI.startswith("mongodb+srv://"):
        return
    if not MONGO_DNS_RESOLVERS:
        return

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = MONGO_DNS_RESOLVERS
    resolver.timeout = MONGO_DNS_TIMEOUT_SECONDS
    resolver.lifetime = max(MONGO_DNS_TIMEOUT_SECONDS * 2, 10)
    dns.resolver.default_resolver = resolver
    print(f"INFO: Using custom DNS resolvers for MongoDB SRV lookups: {', '.join(MONGO_DNS_RESOLVERS)}")


def _connect_mongo(uri):
    client = MongoClient(
        uri,
        serverSelectionTimeoutMS=10000,
        connectTimeoutMS=10000,
        socketTimeoutMS=10000,
        maxPoolSize=20,           # Max 20 connections (prevents exhaustion)
        minPoolSize=5,            # Keep 5 connections warm
        maxIdleTimeMS=45000,      # Close idle connections after 45s
        waitQueueTimeoutMS=5000,  # Timeout if pool is full after 5s
    )
    client.admin.command("ping")
    print("INFO: MongoDB connected with pool: maxPoolSize=20, minPoolSize=5")
    return client


def _print_mongo_connection_hint(uri, exc):
    if not isinstance(exc, OperationFailure):
        return

    message = str(exc)
    if "Authentication failed" not in message:
        return

    print("Hint: MongoDB rejected the username or password for this connection.")
    print("Hint: If your Atlas password contains characters like @, :, /, or #, keep it URL-encoded in Render env vars.")
    print("Hint: Also verify the Render MONGO_URI/MONGO_DIRECT_URI value has no extra quotes, spaces, or outdated password.")
    if uri.startswith("mongodb://") and "authSource=" not in uri:
        print("Hint: Direct Atlas URIs usually need authSource=admin.")


def create_mongo_client():
    tried = []
    connection_options = []
    if MONGO_DIRECT_URI:
        connection_options.append(("MONGO_DIRECT_URI", MONGO_DIRECT_URI))
    if MONGO_URI:
        connection_options.append(("MONGO_URI", MONGO_URI))

    if not connection_options:
        print("\nERROR: MongoDB is not configured.")
        print("Set either MONGO_DIRECT_URI or MONGO_URI in your environment or .env file, then restart the app.")
        sys.exit(1)

    for label, uri in connection_options:
        candidates = build_mongo_uri_candidates(uri, MONGO_DB_NAME)
        for index, candidate in enumerate(candidates, start=1):
            if not candidate or candidate in tried:
                continue
            tried.append(candidate)
            try:
                if len(candidates) > 1:
                    print(f"INFO: Trying {label} candidate {index}/{len(candidates)}")
                return _connect_mongo(candidate)
            except Exception as exc:
                is_last_candidate = index == len(candidates)
                if is_last_candidate:
                    if label == "MONGO_DIRECT_URI" and MONGO_URI:
                        print(f"WARNING: {label} failed, trying MONGO_URI fallback.")
                    elif label == "MONGO_URI" and candidate.startswith("mongodb+srv://") and MONGO_DIRECT_URI:
                        print(f"WARNING: {label} failed, trying MONGO_DIRECT_URI fallback.")
                    else:
                        print(f"WARNING: {label} failed.")
                else:
                    print(f"WARNING: {label} candidate {index} failed, trying authSource fallback.")
                print(f"URI: {redact_mongo_uri(candidate)}")
                print("Reason:", repr(exc))
                _print_mongo_connection_hint(candidate, exc)

    print("\nERROR: Failed to connect to MongoDB.")
    print("Tried these URIs:")
    for uri in tried:
        print(" -", redact_mongo_uri(uri))
    print("\nCommon causes: network/DNS blocking SRV lookups, incorrect URI, or missing dnspython package.")
    sys.exit(1)


# Initialize on import
_configure_srv_dns_resolver()
client = create_mongo_client()
db = client[MONGO_DB_NAME]
fs = GridFS(db)

# Collections
users_collection = db["users"]
items_collection = db["items"]
archived_items_collection = db["archived_items"]
claims_collection = db["claims"]
notifications_collection = db["notifications"]
temp_uploads_collection = db["temp_uploads"]
email_verifications_collection = db["email_verifications"]
item_reports_collection = db["item_reports"]


def initialize_database_indexes():
    temp_uploads_collection.create_index("created_at", expireAfterSeconds=3600)
    users_collection.create_index("email", unique=True)
    item_reports_collection.create_index([("item_id", 1), ("reported_by", 1), ("status", 1)])
    item_reports_collection.create_index("created_at")
    items_collection.create_index([("dup_fingerprint", 1), ("status", 1)])
    email_verifications_collection.create_index("expires_at", expireAfterSeconds=0)
    email_verifications_collection.create_index([("email", 1), ("purpose", 1)], unique=True)
    claims_collection.create_index(
        [("requested_by", 1), ("item_id", 1)],
        unique=True,
        partialFilterExpression={"status": "pending"}
    )
    print("INFO: Database indexes initialized successfully.")
