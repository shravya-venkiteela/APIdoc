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
