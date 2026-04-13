"""
Unit Tests — Configuration Utilities
=====================================
Tests for pure functions in app/config.py:
  - normalize_mongo_uri()
  - build_mongo_uri_candidates()
  - redact_mongo_uri()
  - load_local_env()

These tests import config.py via importlib to avoid triggering
the full app import chain (same technique used in the existing
test_mongo_uri_normalization.py).
"""

import os
import pytest
import importlib.util
import tempfile
from pathlib import Path

# Load config.py directly (no app import needed)
CONFIG_PATH = Path(__file__).resolve().parents[1] / "app" / "config.py"
_spec = importlib.util.spec_from_file_location("config_under_test", CONFIG_PATH)
config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(config)


# ──────────────────────────────────────────────────────────────
#  normalize_mongo_uri()
# ──────────────────────────────────────────────────────────────

class TestNormalizeMongoUri:

    def test_encodes_special_chars_in_password(self):
        uri = "mongodb+srv://user:p@ss:w/ord@cluster0.example.net/?retryWrites=true"
        result = config.normalize_mongo_uri(uri)
        assert "p%40ss%3Aw%2Ford" in result

    def test_preserves_already_encoded_credentials(self):
        uri = "mongodb://user:p%40ss@db.example.net:27017/?authSource=admin"
        assert config.normalize_mongo_uri(uri) == uri

    def test_strips_surrounding_quotes(self):
        uri = '"mongodb://user:pass@host:27017/"'
        result = config.normalize_mongo_uri(uri)
        assert result.startswith("mongodb://")
        assert '"' not in result

    def test_strips_surrounding_single_quotes(self):
        uri = "'mongodb://user:pass@host:27017/'"
        result = config.normalize_mongo_uri(uri)
        assert "'" not in result

    def test_strips_whitespace(self):
        uri = "  mongodb://user:pass@host:27017/  "
        result = config.normalize_mongo_uri(uri)
        assert not result.startswith(" ")
        assert not result.endswith(" ")

    def test_non_mongo_uri_returned_as_is(self):
        uri = "postgresql://user:pass@localhost/db"
        assert config.normalize_mongo_uri(uri) == uri

    def test_no_credentials_returned_as_is(self):
        uri = "mongodb://localhost:27017/"
        assert config.normalize_mongo_uri(uri) == uri

    def test_username_only(self):
        """URI with only username (no colon-separated password)."""
        uri = "mongodb://admin@localhost:27017/"
        result = config.normalize_mongo_uri(uri)
        assert result == "mongodb://admin@localhost:27017/"

    def test_empty_string(self):
        assert config.normalize_mongo_uri("") == ""

    def test_srv_scheme_preserved(self):
        uri = "mongodb+srv://user:pass@cluster.mongodb.net/"
        result = config.normalize_mongo_uri(uri)
        assert result.startswith("mongodb+srv://")


# ──────────────────────────────────────────────────────────────
#  build_mongo_uri_candidates()
# ──────────────────────────────────────────────────────────────

class TestBuildMongoUriCandidates:

    def test_adds_auth_source_fallbacks(self):
        uri = "mongodb://user:pass@db.example.net:27017/?retryWrites=true"
        candidates = config.build_mongo_uri_candidates(uri, "mydb")
        assert len(candidates) == 3
        assert any("authSource=admin" in c for c in candidates)
        assert any("authSource=mydb" in c for c in candidates)

    def test_preserves_existing_auth_source(self):
        uri = "mongodb+srv://u:p@host/?authSource=admin&retryWrites=true"
        candidates = config.build_mongo_uri_candidates(uri, "mydb")
        assert candidates == [uri]

    def test_empty_uri_returns_empty(self):
        assert config.build_mongo_uri_candidates("", "mydb") == []

    def test_non_mongo_uri(self):
        uri = "postgresql://user:pass@localhost/db"
        candidates = config.build_mongo_uri_candidates(uri, "mydb")
        assert candidates == [uri]

    def test_no_at_sign(self):
        uri = "mongodb://localhost:27017/testdb"
        candidates = config.build_mongo_uri_candidates(uri, "mydb")
        assert candidates == [uri]


# ──────────────────────────────────────────────────────────────
#  redact_mongo_uri()
# ──────────────────────────────────────────────────────────────

class TestRedactMongoUri:

    def test_password_masked(self):
        uri = "mongodb://admin:SuperSecret@cluster.net:27017/"
        redacted = config.redact_mongo_uri(uri)
        assert "SuperSecret" not in redacted
        assert "***" in redacted

    def test_srv_password_masked(self):
        uri = "mongodb+srv://user:TopSecret@cluster.mongodb.net/"
        redacted = config.redact_mongo_uri(uri)
        assert "TopSecret" not in redacted
        assert "***" in redacted

    def test_no_credentials_unchanged(self):
        uri = "mongodb://localhost:27017/"
        assert config.redact_mongo_uri(uri) == uri


# ──────────────────────────────────────────────────────────────
#  load_local_env()
# ──────────────────────────────────────────────────────────────

class TestLoadLocalEnv:

    def test_loads_key_value_pairs(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("MY_TEST_VAR_12345=hello_world\n")
        # Clear any previous value
        os.environ.pop("MY_TEST_VAR_12345", None)
        config.load_local_env(str(env_file))
        assert os.environ.get("MY_TEST_VAR_12345") == "hello_world"
        # Cleanup
        os.environ.pop("MY_TEST_VAR_12345", None)

    def test_skips_comments_and_blanks(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("# comment\n\nVALID_KEY_99=yes\n")
        os.environ.pop("VALID_KEY_99", None)
        config.load_local_env(str(env_file))
        assert os.environ.get("VALID_KEY_99") == "yes"
        os.environ.pop("VALID_KEY_99", None)

    def test_does_not_override_existing(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET_KEY=overridden_value\n")
        # SECRET_KEY is already set by conftest
        config.load_local_env(str(env_file))
        assert os.environ["SECRET_KEY"] != "overridden_value"

    def test_nonexistent_file_no_error(self):
        """Loading a non-existent file should silently return."""
        config.load_local_env("/nonexistent/path/.env")  # Should not raise

    def test_strips_quotes_from_values(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text('QUOTED_VAR_TEST="hello"\n')
        os.environ.pop("QUOTED_VAR_TEST", None)
        config.load_local_env(str(env_file))
        assert os.environ.get("QUOTED_VAR_TEST") == "hello"
        os.environ.pop("QUOTED_VAR_TEST", None)
