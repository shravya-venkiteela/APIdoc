"""Minimal HS256 JWTs for the mock API (no external dependency).

The secret is public on purpose: this is a test server. Real services must
never hard-code a signing key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

SECRET = b"apidoc-mock-signing-key-not-secret"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def mint(
    sub: str = "demo",
    scope: str = "read",
    ttl: int = 3600,
    nbf_offset: int = 0,
    now: float | None = None,
) -> str:
    """ttl < 0 gives an already-expired token; nbf_offset > 0 one that is not valid yet."""
    now = int(now if now is not None else time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {
        "sub": sub,
        "scope": scope,
        "iat": now,
        "nbf": now + nbf_offset,
        "exp": now + ttl,
        "jti": secrets.token_hex(8),  # unique per token, as real servers do
    }
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}"
    sig = hmac.new(SECRET, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(sig)}"


class TokenError(ValueError):
    pass


def verify(token: str, now: float | None = None, leeway: int = 30) -> dict:
    now = now if now is not None else time.time()
    try:
        head, body, sig = token.split(".")
        expected = hmac.new(SECRET, f"{head}.{body}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(sig)):
            raise TokenError("bad signature")
        claims = json.loads(_unb64(body))
    except (ValueError, json.JSONDecodeError) as exc:
        raise TokenError(f"malformed token: {exc}") from exc
    if claims.get("exp", 0) < now - leeway:
        raise TokenError("token expired")
    if claims.get("nbf", 0) > now + leeway:
        raise TokenError("token not yet valid")
    return claims
