from fastapi.testclient import TestClient

from mock_server.app import app

client = TestClient(app, base_url="http://localhost:8000")


def test_me_ok():
    r = client.get("/v1/me", headers={"Authorization": "Bearer good-token"})
    assert r.status_code == 200
    assert r.json() == {"user": "demo"}


def test_me_missing_header():
    r = client.get("/v1/me")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_me_wrong_token():
    r = client.get("/v1/me", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401
    assert 'error="invalid_token"' in r.headers["www-authenticate"]


def test_items_wrong_content_type():
    r = client.post("/v1/items", content="name=x", headers={"Content-Type": "text/plain"})
    assert r.status_code == 415


def test_items_invalid_json_is_vague():
    r = client.post("/v1/items", content="{name: x}", headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    assert r.json() == {"error": "bad request"}


def test_items_ok():
    r = client.post("/v1/items", json={"name": "x"})
    assert r.status_code == 201


def test_old_me_redirects_to_other_host():
    r = client.get("/v1/old-me", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "http://127.0.0.1:8000/v1/me"


def test_jwt_accepted_and_expired_rejected():
    from mock_server import tokens

    ok = client.get("/v1/me", headers={"Authorization": f"Bearer {tokens.mint()}"})
    assert ok.status_code == 200
    old = client.get("/v1/me", headers={"Authorization": f"Bearer {tokens.mint(ttl=-3600)}"})
    assert old.status_code == 401
    assert "token expired" in old.headers["www-authenticate"]


# ---------- held-out endpoints (evals/heldout.json) -------------------------


def test_heldout_endpoints_fail_as_designed():
    assert client.get("/v1/orders?status=Shipped").status_code == 400
    assert client.get("/v1/orders?status=shipped").status_code == 200
    r = client.post("/graphql", json={"query": "{ user(id: 1) { name emial } }"})
    assert r.status_code == 200 and "Did you mean" in r.json()["errors"][0]["message"]
    r = client.get("/v1/reports", headers={"X-API-Key": "key-2023-old"})
    assert r.status_code == 403 and r.headers["x-error-reason"] == "api key revoked"
    r = client.get("/v1/catalog?page=7")
    assert r.status_code == 404 and r.headers["x-total-pages"] == "3"
    assert client.get("/v1/billing").status_code == 400
    assert client.get("/v1/billing", headers={"Api-Version": "2025-01-01"}).status_code == 200
    assert client.post("/v1/charges", json={"amount": 500}).status_code == 428
    r = client.get("/v1/account", auth=("demo", "hunter2-pass"))
    assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Bearer")
    assert client.get("/v1/files/report.csv?X-Expires=1700000000").status_code == 403
    assert client.get("/v1/repos").headers["x-ratelimit-remaining"] == "0"
    r = client.get("/v1/profile", headers={"Authorisation": "Bearer good-token"})
    assert r.status_code == 401
