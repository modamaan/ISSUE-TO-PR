"""HMAC-SHA256 webhook signature verification.

GitHub signs every webhook POST with a header:
    X-Hub-Signature-256: sha256=<hex_digest>

We verify this using hmac.compare_digest (constant-time) to prevent
timing attacks.
"""

from __future__ import annotations

import hashlib
import hmac


def verify_signature(body: bytes, signature_header: str, secret: str) -> bool:
    """Return True iff the HMAC-SHA256 signature is valid.

    Args:
        body: Raw request body bytes.
        signature_header: Value of X-Hub-Signature-256 header.
        secret: Webhook secret (plaintext string).

    Returns:
        True if the signature matches, False otherwise.
    """
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected = hmac.new(
        key=secret.encode(),
        msg=body,
        digestmod=hashlib.sha256,
    ).hexdigest()

    # constant-time comparison to prevent timing attacks
    return hmac.compare_digest(f"sha256={expected}", signature_header)
