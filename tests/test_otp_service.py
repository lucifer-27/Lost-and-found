"""
Unit Tests — OTP Service
=========================
Tests for app/services/otp_service.py → generate_otp()

The OTP generator produces a 6-digit numeric one-time code using
the secrets module.  Tests verify length, character set, and
statistical uniqueness.
"""

import pytest
from app.services.otp_service import generate_otp


class TestGenerateOtp:

    def test_returns_string(self):
        """OTP should be a string."""
        otp = generate_otp()
        assert isinstance(otp, str)

    def test_length_is_six(self):
        """OTP should always be exactly 6 digits long."""
        for _ in range(20):
            assert len(generate_otp()) == 6

    def test_only_digits(self):
        """OTP should contain only numeric characters (0-9)."""
        for _ in range(20):
            otp = generate_otp()
            assert otp.isdigit(), f"Non-digit character in OTP: {otp}"

    def test_randomness(self):
        """Generating many OTPs should produce variety (not always the same)."""
        otps = {generate_otp() for _ in range(50)}
        # With 6 digits, 50 random draws should yield at least 10 unique values
        assert len(otps) >= 10, "OTP generation appears non-random"

    def test_includes_zero_padding(self):
        """OTPs like '000123' should remain zero-padded to 6 digits."""
        # Generate many OTPs and ensure length never drops
        for _ in range(100):
            otp = generate_otp()
            assert len(otp) == 6
