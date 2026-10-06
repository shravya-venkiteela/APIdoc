import base64
import hashlib

import httpx
import pytest

from apidoc import oauth


def browser(url: str) -> None:
    httpx.get(url, follow_redirects=True, timeout=10)


def mock_cfg(live_server, client_id="demo-cli", scope="read"):
    return oauth.preset("mock", live_server, client_id, scope)


def test_pkce_pair_matches_rfc7636():
    verifier, challenge = oauth.pkce_pair()
    assert 43 <= len(verifier) <= 128
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    assert challenge == expected.rstrip(b"=").decode()
    assert oauth.pkce_pair()[0] != verifier  # random every time


def test_pkce_login_gets_a_working_token(live_server):
    tok = oauth.login_pkce(mock_cfg(live_server, scope="read admin"), open_browser=browser)
    assert tok.refresh_token and not tok.expired
    assert tok.scope == "admin read"
    r = httpx.get(
        f"{live_server}/v1/admin/users", headers={"Authorization": f"Bearer {tok.access_token}"}
    )
    assert r.status_code == 200


def test_state_mismatch_is_rejected(live_server):
    def tampering_browser(url: str) -> None:
        browser(url.replace("state=", "state=attacker"))

    with pytest.raises(oauth.OAuthError, match="state mismatch"):
        oauth.login_pkce(mock_cfg(live_server), open_browser=tampering_browser)


def test_server_error_is_reported(live_server):
    with pytest.raises(oauth.OAuthError, match="invalid_scope"):
        oauth.login_pkce(mock_cfg(live_server, scope="superuser"), open_browser=browser)


def test_refresh_rotates_the_refresh_token(live_server):
    cfg = mock_cfg(live_server)
    first = oauth.login_pkce(cfg, open_browser=browser)
    second = oauth.refresh(cfg, first.refresh_token)
    assert second.access_token and second.refresh_token != first.refresh_token
    with pytest.raises(oauth.OAuthError, match="invalid_grant"):
        oauth.refresh(cfg, first.refresh_token)  # old one is single-use


def _authorize(live_server, challenge, redirect="http://127.0.0.1:9/cb"):
    r = httpx.get(
        f"{live_server}/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo-cli",
            "redirect_uri": redirect,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "s",
        },
    )
    return r


def _code(live_server, challenge):
    location = _authorize(live_server, challenge).headers["location"]
    return httpx.URL(location).params["code"]


def test_wrong_verifier_is_rejected(live_server):
    verifier, challenge = oauth.pkce_pair()
    r = httpx.post(
        f"{live_server}/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": _code(live_server, challenge),
            "redirect_uri": "http://127.0.0.1:9/cb",
            "client_id": "demo-cli",
            "code_verifier": "not-the-verifier-" + "x" * 30,
        },
    )
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_codes_are_single_use(live_server):
    verifier, challenge = oauth.pkce_pair()
    form = {
        "grant_type": "authorization_code",
        "code": _code(live_server, challenge),
        "redirect_uri": "http://127.0.0.1:9/cb",
        "client_id": "demo-cli",
        "code_verifier": verifier,
    }
    assert httpx.post(f"{live_server}/oauth/token", data=form).status_code == 200
    assert httpx.post(f"{live_server}/oauth/token", data=form).json()["error"] == "invalid_grant"


def test_non_loopback_redirect_is_refused_without_redirecting(live_server):
    r = _authorize(live_server, "c" * 43, redirect="https://evil.example/cb")
    assert r.status_code == 400  # an error page, not a redirect to the attacker


def test_token_responses_are_not_cacheable(live_server):
    tok = httpx.post(
        f"{live_server}/oauth/token",
        data={"grant_type": "client_credentials"},
        auth=("demo-service", "demo-service-secret"),
    )
    assert tok.headers["cache-control"] == "no-store"


def test_client_credentials(live_server):
    tok = oauth.client_credentials(
        mock_cfg(live_server, "demo-service", "admin"), "demo-service-secret"
    )
    assert tok.scope == "admin" and tok.refresh_token is None


def test_client_credentials_wrong_secret(live_server):
    with pytest.raises(oauth.OAuthError, match="invalid_client"):
        oauth.client_credentials(mock_cfg(live_server, "demo-service"), "wrong")


def test_unknown_provider():
    with pytest.raises(oauth.OAuthError, match="unknown provider"):
        oauth.preset("myspace", "", "x")
