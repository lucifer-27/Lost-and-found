"""
Unit Tests — Image Service
===========================
Tests for pure helper functions in app/services/image_service.py:
  - normalize_image_content_type()
  - build_item_image_fields()
  - build_data_image_src()
  - extract_item_image_src()

These functions handle image encoding, MIME type normalization,
and base64 data-URI construction.
"""

import base64
import pytest
from bson.binary import Binary
from app.services.image_service import (
    normalize_image_content_type,
    build_item_image_fields,
    build_data_image_src,
    extract_item_image_src,
    DEFAULT_IMAGE_CONTENT_TYPE,
)


# ──────────────────────────────────────────────────────────────
#  normalize_image_content_type()
# ──────────────────────────────────────────────────────────────

class TestNormalizeImageContentType:

    def test_valid_jpeg(self):
        assert normalize_image_content_type("image/jpeg") == "image/jpeg"

    def test_valid_png(self):
        assert normalize_image_content_type("image/png") == "image/png"

    def test_valid_webp(self):
        assert normalize_image_content_type("image/webp") == "image/webp"

    def test_invalid_type_falls_back_to_default(self):
        assert normalize_image_content_type("application/pdf") == DEFAULT_IMAGE_CONTENT_TYPE

    def test_none_falls_back_to_default(self):
        assert normalize_image_content_type(None) == DEFAULT_IMAGE_CONTENT_TYPE

    def test_empty_string_falls_back_to_default(self):
        assert normalize_image_content_type("") == DEFAULT_IMAGE_CONTENT_TYPE


# ──────────────────────────────────────────────────────────────
#  build_item_image_fields()
# ──────────────────────────────────────────────────────────────

class TestBuildItemImageFields:

    def test_no_image_returns_none_fields(self):
        fields = build_item_image_fields()
        assert fields["image"] is None
        assert fields["image_content_type"] is None
        assert fields["image_filename"] is None

    def test_with_image_bytes(self):
        data = b"\x89PNG\r\n\x1a\n"  # PNG header bytes
        fields = build_item_image_fields(
            image_bytes=data,
            content_type="image/png",
            filename="test.png",
        )
        assert isinstance(fields["image"], Binary)
        assert fields["image_content_type"] == "image/png"
        assert fields["image_filename"] == "test.png"

    def test_with_image_bytes_no_filename(self):
        fields = build_item_image_fields(image_bytes=b"data", content_type="image/jpeg")
        assert fields["image_filename"] is None

    def test_invalid_content_type_normalized(self):
        fields = build_item_image_fields(image_bytes=b"data", content_type="text/plain")
        assert fields["image_content_type"] == DEFAULT_IMAGE_CONTENT_TYPE


# ──────────────────────────────────────────────────────────────
#  build_data_image_src()
# ──────────────────────────────────────────────────────────────

class TestBuildDataImageSrc:

    def test_returns_data_uri(self):
        data = b"hello"
        result = build_data_image_src(data, "image/png")
        expected_b64 = base64.b64encode(data).decode("ascii")
        assert result == f"data:image/png;base64,{expected_b64}"

    def test_none_image_returns_none(self):
        assert build_data_image_src(None, "image/png") is None

    def test_empty_bytes_returns_none(self):
        assert build_data_image_src(b"", "image/png") is None

    def test_normalizes_invalid_content_type(self):
        result = build_data_image_src(b"data", "application/octet-stream")
        assert result.startswith(f"data:{DEFAULT_IMAGE_CONTENT_TYPE};base64,")


# ──────────────────────────────────────────────────────────────
#  extract_item_image_src()
# ──────────────────────────────────────────────────────────────

class TestExtractItemImageSrc:

    def test_binary_image(self):
        item = {"image": Binary(b"img_data"), "image_content_type": "image/jpeg"}
        src = extract_item_image_src(item)
        assert src is not None
        assert src.startswith("data:image/jpeg;base64,")

    def test_bytes_image(self):
        item = {"image": b"raw_bytes", "image_content_type": "image/png"}
        src = extract_item_image_src(item)
        assert src is not None
        assert "base64," in src

    def test_string_data_uri_passthrough(self):
        data_uri = "data:image/png;base64,iVBORw0KGgo="
        item = {"image": data_uri}
        assert extract_item_image_src(item) == data_uri

    def test_string_base64_without_prefix(self):
        item = {"image": "aGVsbG8=", "image_content_type": "image/png"}
        src = extract_item_image_src(item)
        assert src == "data:image/png;base64,aGVsbG8="

    def test_no_image_returns_none(self):
        item = {"name": "Laptop"}
        assert extract_item_image_src(item) is None

    def test_none_image_value_returns_none(self):
        item = {"image": None}
        assert extract_item_image_src(item) is None
