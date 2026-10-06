from __future__ import annotations

import base64
import hashlib
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from mock_server import tokens

router = APIRouter()

CLIENTS = {
    # Public client (a CLI or desktop app): no secret, must use PKCE.
    "demo-cli": {"secret": None, "scopes": {"read", "write", "admin"}},
    # Confidential client (a backend service): client credentials grant.
    "demo-service": {"secret": "demo-service-secret", "scopes": {"read", "admin"}},
}
CODE_TTL = 60
ACCESS_TTL = 3600

_codes: dict[str, dict] = {}
_refresh_tokens: dict[str, dict] = {}


def _error(error: str, description: str, status: int = 400) -> JSONResponse:
    headers = {"WWW-Authenticate": 'Basic realm="oauth"'} if status == 401 else None
    return JSONResponse(
        {"error": error, "error_description": description}, status_code=status, headers=headers
    )


def _is_loopback(uri: str) -> bool:
    """RFC 8252: native apps use a loopback redirect on any port."""
    parts = urlsplit(uri)
    return parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost")


def _scopes(requested: str, client_id: str) -> set[str] | None:
    wanted = set(requested.split()) if requested else {"read"}
    return wanted if wanted <= CLIENTS[client_id]["scopes"] else None


def _token_response(client_id: str, scope: set[str], ttl: int, refresh: bool) -> JSONResponse:
    body = {
        "access_token": tokens.mint(sub=client_id, scope=" ".join(sorted(scope)), ttl=ttl),
        "token_type": "Bearer",
        "expires_in": ttl,
        "scope": " ".join(sorted(scope)),
    }
    if refresh:
        rt = secrets.token_urlsafe(32)
        _refresh_tokens[rt] = {"client_id": client_id, "scope": scope}
        body["refresh_token"] = rt
    # RFC 6749 5.1: token responses must not be cached.
    return JSONResponse(body, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@router.get("/oauth/authorize")
async def authorize(request: Request):
    q = request.query_params
    client_id, redirect_uri, state = q.get("client_id"), q.get("redirect_uri", ""), q.get("state")
    if client_id not in CLIENTS:
        return _error("invalid_client", "unknown client_id")
    if not _is_loopback(redirect_uri):
        # Never redirect to an unvalidated URI: report the error directly.
        return _error("invalid_request", "redirect_uri must be a loopback http URL")

    def back(**params) -> RedirectResponse:
        if state:
            params["state"] = state
        return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)

    if q.get("response_type") != "code":
        return back(error="unsupported_response_type")
    if q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
        return back(error="invalid_request", error_description="PKCE with S256 is required")
    scope = _scopes(q.get("scope", ""), client_id)
    if scope is None:
        return back(error="invalid_scope")

    code = secrets.token_urlsafe(24)
    _codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "challenge": q["code_challenge"],
        "scope": scope,
        "expires": time.time() + CODE_TTL,
    }
    return back(code=code)


def _client_auth(request: Request, form: dict[str, str]) -> tuple[str | None, str | None]:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("basic "):
        try:
            cid, _, secret = base64.b64decode(header[6:]).decode().partition(":")
            return cid, secret
        except ValueError:
            return None, None
    return form.get("client_id"), form.get("client_secret")


@router.post("/oauth/token")
async def token(request: Request):
    # Parsed by hand: avoids FastAPI's dependency on python-multipart.
    raw = parse_qs((await request.body()).decode(), keep_blank_values=True)
    form = {k: v[0] for k, v in raw.items()}
    grant = form.get("grant_type")
    ttl = int(form.get("ttl", ACCESS_TTL))  # mock-only, see module docstring

    if grant == "authorization_code":
        entry = _codes.pop(form.get("code", ""), None)  # pop: codes are single-use
        if entry is None or entry["expires"] < time.time():
            return _error("invalid_grant", "unknown, used or expired code")
        if form.get("client_id") != entry["client_id"]:
            return _error("invalid_grant", "code was issued to another client")
        if form.get("redirect_uri") != entry["redirect_uri"]:
            return _error("invalid_grant", "redirect_uri does not match")
        verifier = form.get("code_verifier", "")
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if not secrets.compare_digest(challenge, entry["challenge"]):
            return _error("invalid_grant", "PKCE verification failed")
        return _token_response(entry["client_id"], entry["scope"], ttl, refresh=True)

    if grant == "client_credentials":
        cid, secret = _client_auth(request, form)
        client = CLIENTS.get(cid or "")
        if not client or not client["secret"] or not secret:
            return _error("invalid_client", "client authentication failed", status=401)
        if not secrets.compare_digest(secret, client["secret"]):
            return _error("invalid_client", "client authentication failed", status=401)
        scope = _scopes(form.get("scope", ""), cid)
        if scope is None:
            return _error("invalid_scope", f"allowed scopes: {' '.join(sorted(client['scopes']))}")
        return _token_response(cid, scope, ttl, refresh=False)

    if grant == "refresh_token":
        entry = _refresh_tokens.pop(form.get("refresh_token", ""), None)  # rotated on use
        if entry is None:
            return _error("invalid_grant", "unknown or already used refresh token")
        return _token_response(entry["client_id"], entry["scope"], ttl, refresh=True)

    return _error("unsupported_grant_type", f"grant_type {grant!r} is not supported")
