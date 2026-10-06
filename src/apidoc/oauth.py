from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import time
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from pydantic import BaseModel


class OAuthError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProviderConfig:
    authorize_url: str
    token_url: str
    client_id: str
    scope: str = ""


def preset(name: str, base_url: str, client_id: str, scope: str = "") -> ProviderConfig:
    """Known providers. Only 'mock' is tested; github/google need an OAuth app
    registered with the provider (with a loopback redirect URI)."""
    if name == "mock":
        base = base_url.rstrip("/")
        return ProviderConfig(f"{base}/oauth/authorize", f"{base}/oauth/token", client_id, scope)
    if name == "github":
        return ProviderConfig(
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            client_id,
            scope,
        )
    if name == "google":
        return ProviderConfig(
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            client_id,
            scope or "openid email",
        )
    raise OAuthError(f"unknown provider {name!r} (mock, github, google)")


class TokenSet(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    refresh_token: str | None = None
    scope: str = ""
    expires_at: float | None = None  # unix time

    @property
    def expired(self) -> bool:
        return self.expires_at is not None and self.expires_at < time.time()


def pkce_pair() -> tuple[str, str]:
    """(code_verifier, code_challenge). The verifier never leaves this machine
    until the token exchange; an intercepted code is useless without it."""
    verifier = secrets.token_urlsafe(64)[:96]  # RFC 7636: 43-128 characters
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


class _CallbackServer:
    """One-shot loopback listener that captures the authorization response."""

    def __init__(self) -> None:
        self.params: dict[str, str] = {}
        self.received = threading.Event()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 (http.server naming)
                query = parse_qs(urlsplit(self.path).query)
                outer.params = {k: v[0] for k, v in query.items()}
                outer.received.set()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<p>APIdoc: you can close this window.</p>")

            def log_message(self, *args) -> None:  # silence: the URL holds the code
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.redirect_uri = f"http://127.0.0.1:{self.server.server_port}/callback"

    def start(self) -> None:
        """Serve before the browser is opened: a fast redirect must find a listener."""
        self._thread = threading.Thread(target=self.server.handle_request, daemon=True)
        self._thread.start()

    def wait(self, timeout: float) -> dict[str, str]:
        if not self.received.wait(timeout):
            self.server.server_close()
            raise OAuthError(f"no response from the browser within {timeout:.0f}s")
        self._thread.join(1)
        self.server.server_close()
        return self.params


def login_pkce(
    cfg: ProviderConfig,
    *,
    open_browser: Callable[[str], object] = webbrowser.open,
    timeout: float = 120.0,
    transport: httpx.BaseTransport | None = None,
    extra_token_params: dict[str, str] | None = None,
) -> TokenSet:
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)
    callback = _CallbackServer()
    query = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": callback.redirect_uri,
        "scope": cfg.scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    callback.start()
    open_browser(f"{cfg.authorize_url}?{urlencode(query)}")
    params = callback.wait(timeout)

    if not secrets.compare_digest(params.get("state", ""), state):
        raise OAuthError("state mismatch: the response did not come from this login attempt")
    if "error" in params:
        raise OAuthError(f"{params['error']}: {params.get('error_description', '')}".strip(": "))
    if "code" not in params:
        raise OAuthError("the authorization server returned no code")

    return _token_request(
        cfg,
        {
            "grant_type": "authorization_code",
            "code": params["code"],
            "redirect_uri": callback.redirect_uri,
            "client_id": cfg.client_id,
            "code_verifier": verifier,
            **(extra_token_params or {}),
        },
        transport=transport,
    )


def client_credentials(
    cfg: ProviderConfig,
    client_secret: str,
    *,
    transport: httpx.BaseTransport | None = None,
    extra_token_params: dict[str, str] | None = None,
) -> TokenSet:
    form = {"grant_type": "client_credentials", **(extra_token_params or {})}
    if cfg.scope:
        form["scope"] = cfg.scope
    # HTTP Basic is the method every server must support (RFC 6749 2.3.1).
    return _token_request(cfg, form, auth=(cfg.client_id, client_secret), transport=transport)


def refresh(
    cfg: ProviderConfig,
    refresh_token: str,
    *,
    transport: httpx.BaseTransport | None = None,
) -> TokenSet:
    form = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": cfg.client_id,
    }
    return _token_request(cfg, form, transport=transport)


def _token_request(
    cfg: ProviderConfig,
    form: dict[str, str],
    *,
    auth: tuple[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
) -> TokenSet:
    with httpx.Client(transport=transport, timeout=30) as client:
        # Accept JSON: GitHub answers form-encoded otherwise.
        r = client.post(cfg.token_url, data=form, auth=auth, headers={"Accept": "application/json"})
    try:
        body = r.json()
    except ValueError as exc:
        raise OAuthError(f"token endpoint returned {r.status_code} and no JSON") from exc
    if r.status_code >= 400 or "error" in body:
        raise OAuthError(f"{body.get('error', r.status_code)}: {body.get('error_description', '')}")
    if "access_token" not in body:
        raise OAuthError("token response has no access_token")
    expires_in = body.get("expires_in")
    return TokenSet(
        access_token=body["access_token"],
        token_type=body.get("token_type", "Bearer"),
        refresh_token=body.get("refresh_token"),
        scope=body.get("scope", cfg.scope),
        expires_at=time.time() + float(expires_in) if expires_in is not None else None,
    )
