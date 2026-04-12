import sys
import dns.resolver
from pymongo import MongoClient
from gridfs import GridFS
from .config import (
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
    default_limits=[]
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
        if not uri or uri in tried:
            continue
        tried.append(uri)
        try:
            return _connect_mongo(uri)
        except Exception as exc:
            if label == "MONGO_DIRECT_URI" and MONGO_URI:
                print(f"WARNING: {label} failed, trying MONGO_URI fallback.")
            elif label == "MONGO_URI" and uri.startswith("mongodb+srv://") and MONGO_DIRECT_URI:
                print(f"WARNING: {label} failed, trying MONGO_DIRECT_URI fallback.")
            else:
                print(f"WARNING: {label} failed.")
            print(f"URI: {redact_mongo_uri(uri)}")
            print("Reason:", repr(exc))

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
temp_uploads_collection.create_index("created_at", expireAfterSeconds=3600)
users_collection.create_index("email", unique=True)
item_reports_collection.create_index([("item_id", 1), ("reported_by", 1), ("status", 1)])
item_reports_collection.create_index("created_at")
items_collection.create_index([("dup_fingerprint", 1), ("status", 1)])

email_verifications_collection.create_index("expires_at", expireAfterSeconds=0)
email_verifications_collection.create_index([("email", 1), ("purpose", 1)], unique=True)
# CLAIM DUPLICATION
claims_collection.create_index(
    [("requested_by", 1), ("item_id", 1)],
    unique=True,
    partialFilterExpression={"status": "pending"}
)
