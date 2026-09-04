"""Unit tests for HMAC webhook signature verification."""

from __future__ import annotations

import hashlib
import hmac

from api.verifier import verify_signature


def _make_signature(body: bytes, secret: str) -> str:
    digest = hmac.new(
        key=secret.encode(),
        msg=body,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


class TestVerifySignature:
    """Tests for the HMAC-SHA256 verifier."""

    def test_valid_signature_passes(self):
        body = b'{"action": "opened"}'
        secret = "my-webhook-secret"
        sig = _make_signature(body, secret)
        assert verify_signature(body, sig, secret) is True

    def test_invalid_signature_fails(self):
        body = b'{"action": "opened"}'
        secret = "my-webhook-secret"
        assert verify_signature(body, "sha256=deadbeef", secret) is False

    def test_wrong_secret_fails(self):
        body = b'{"action": "opened"}'
        sig = _make_signature(body, "correct-secret")
        assert verify_signature(body, sig, "wrong-secret") is False

    def test_tampered_body_fails(self):
        body = b'{"action": "opened"}'
        secret = "my-webhook-secret"
        sig = _make_signature(body, secret)
        tampered = b'{"action": "deleted"}'
        assert verify_signature(tampered, sig, secret) is False

    def test_missing_sha256_prefix_fails(self):
        body = b'hello'
        secret = "secret"
        # Missing 'sha256=' prefix
        raw_hex = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        assert verify_signature(body, raw_hex, secret) is False

    def test_empty_signature_fails(self):
        assert verify_signature(b"body", "", "secret") is False

    def test_empty_body_valid_signature_passes(self):
        body = b""
        secret = "secret"
        sig = _make_signature(body, secret)
        assert verify_signature(body, sig, secret) is True

    def test_unicode_secret_handled(self):
        body = b'{"data": "value"}'
        secret = "secret-with-special-chars-!@#$%"
        sig = _make_signature(body, secret)
        assert verify_signature(body, sig, secret) is True

    def test_large_payload(self):
        body = b"x" * 100_000
        secret = "large-body-secret"
        sig = _make_signature(body, secret)
        assert verify_signature(body, sig, secret) is True

    def test_constant_time_comparison(self):
        """Verify we use compare_digest (not ==) — checked by inspecting code."""
        import inspect  # noqa: PLC0415

        from api import verifier  # noqa: PLC0415

        source = inspect.getsource(verifier)
        assert "compare_digest" in source, "Must use hmac.compare_digest for timing safety"
