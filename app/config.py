import os
import re
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


# Load .env files
load_dotenv(os.path.join(project_root, ".env"))
load_local_env(os.path.join(project_root, ".env"))
load_local_env(os.path.join(basedir, ".env"))

# Mongo config
MONGO_URI = os.environ.get("MONGO_URI", "").strip()
MONGO_DIRECT_URI = os.environ.get("MONGO_DIRECT_URI", "").strip()
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "lost_found_db")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev_secret_key")


def redact_mongo_uri(uri):
    return re.sub(r"(mongodb(?:\+srv)?://[^:]+:)[^@]+@", r"\1***@", uri)
