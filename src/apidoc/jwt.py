"""Read a JWT's claims without verifying it.

APIdoc never has the signing key and does not need it: it only wants to know
whether `exp` is in the past or `nbf` in the future. Only time and scope
claims leave this module; `sub`, emails and the like are never surfaced.
"""

from __future__ import annotations

import base64
import json
import re

_JWT = re.compile(r"^[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]*$")
SAFE_CLAIMS = ("exp", "nbf", "iat", "scope", "scp", "aud", "iss")


def claims(token: str) -> dict | None:
    match = _JWT.match(token.strip())
    if not match:
        return None
    payload = match.group(1)
    try:
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return {k: data[k] for k in SAFE_CLAIMS if k in data}


def bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None
