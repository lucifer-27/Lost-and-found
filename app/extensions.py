import sys
from pymongo import MongoClient
from gridfs import GridFS
from .config import MONGO_URI, MONGO_DIRECT_URI, MONGO_DB_NAME, redact_mongo_uri


def _connect_mongo(uri):
    client = MongoClient(
        uri,
        serverSelectionTimeoutMS=10000,
        connectTimeoutMS=10000,
        socketTimeoutMS=10000,
    )
    client.admin.command("ping")
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
temp_uploads_collection.create_index("created_at", expireAfterSeconds=3600)
