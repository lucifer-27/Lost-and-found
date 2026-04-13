import importlib.util
from pathlib import Path


CONFIG_PATH = Path(__file__).resolve().parents[1] / "app" / "config.py"
SPEC = importlib.util.spec_from_file_location("lost_found_config_for_tests", CONFIG_PATH)
config = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(config)


def test_normalize_mongo_uri_encodes_reserved_password_characters():
    uri = "mongodb+srv://lostfound:p@ss:w/or#d@cluster0.example.mongodb.net/?retryWrites=true&w=majority"

    normalized = config.normalize_mongo_uri(uri)

    assert normalized == (
        "mongodb+srv://lostfound:p%40ss%3Aw%2For%23d@"
        "cluster0.example.mongodb.net/?retryWrites=true&w=majority"
    )


def test_normalize_mongo_uri_preserves_already_encoded_credentials():
    uri = "mongodb://lostfound:p%40ss@db.example.net:27017/?authSource=admin"

    normalized = config.normalize_mongo_uri(uri)

    assert normalized == uri


def test_build_mongo_uri_candidates_adds_admin_and_db_auth_source_fallbacks():
    uri = "mongodb://lostfound:pass@db.example.net:27017/?retryWrites=true"

    candidates = config.build_mongo_uri_candidates(uri, "lost_found_db")

    assert candidates == [
        "mongodb://lostfound:pass@db.example.net:27017/?retryWrites=true",
        "mongodb://lostfound:pass@db.example.net:27017/?retryWrites=true&authSource=admin",
        "mongodb://lostfound:pass@db.example.net:27017/?retryWrites=true&authSource=lost_found_db",
    ]


def test_build_mongo_uri_candidates_preserves_existing_auth_source():
    uri = "mongodb+srv://lostfound:pass@cluster0.example.mongodb.net/?authSource=admin&retryWrites=true"

    candidates = config.build_mongo_uri_candidates(uri, "lost_found_db")

    assert candidates == [uri]
