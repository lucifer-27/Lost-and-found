import os
import re
from urllib.parse import quote, unquote
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
project_root = os.path.abspath(os.path.join(basedir, os.pardir))


def load_local_env(env_path):
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def normalize_mongo_uri(uri):
    uri = uri.strip().strip('"').strip("'")
    if not uri.startswith(("mongodb://", "mongodb+srv://")):
        return uri

    scheme, remainder = uri.split("://", 1)
    at_index = remainder.rfind("@")
    if at_index == -1:
        return uri

    credentials = remainder[:at_index]
    host_and_rest = remainder[at_index + 1:]

    host_boundary = len(host_and_rest)
    for separator in ("/", "?"):
        index = host_and_rest.find(separator)
        if index != -1:
            host_boundary = min(host_boundary, index)

    hosts = host_and_rest[:host_boundary]
    rest = host_and_rest[host_boundary:]
    if not hosts:
        return uri

    if ":" in credentials:
        username, password = credentials.split(":", 1)
        safe_credentials = (
            f"{quote(unquote(username), safe='')}:"
            f"{quote(unquote(password), safe='')}"
        )
    else:
        safe_credentials = quote(unquote(credentials), safe="")

    return f"{scheme}://{safe_credentials}@{hosts}{rest}"


# Load .env files
load_dotenv(os.path.join(project_root, ".env"))
load_local_env(os.path.join(project_root, ".env"))
load_local_env(os.path.join(basedir, ".env"))

# Mongo config
MONGO_URI = normalize_mongo_uri(os.environ.get("MONGO_URI", ""))
MONGO_DIRECT_URI = normalize_mongo_uri(os.environ.get("MONGO_DIRECT_URI", ""))
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "lost_found_db")
MONGO_DNS_RESOLVERS = [resolver.strip() for resolver in os.environ.get("MONGO_DNS_RESOLVERS", "1.1.1.1,8.8.8.8").split(",") if resolver.strip()]
MONGO_DNS_TIMEOUT_SECONDS = float(os.environ.get("MONGO_DNS_TIMEOUT_SECONDS", "5"))
_env_mode = os.environ.get("ENV", "development").lower()
SECRET_KEY = os.environ.get("SECRET_KEY")

if not SECRET_KEY:
    if _env_mode == "production":
        raise ValueError(
            "CRITICAL: SECRET_KEY environment variable not set! "
            "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
        )
    else:
        SECRET_KEY = "dev_only_insecure_key_do_not_use_in_production"
        print("WARNING: Using insecure dev SECRET_KEY. Set SECRET_KEY env var for production.")


def redact_mongo_uri(uri):
    return re.sub(r"(mongodb(?:\+srv)?://[^:]+:)[^@]+@", r"\1***@", uri)
