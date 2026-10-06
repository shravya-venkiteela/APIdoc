from __future__ import annotations

import json
from datetime import date

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from mock_server import tokens

app = FastAPI(title="APIdoc mock API")

GOOD_TOKEN = "good-token"
GOOD_API_KEY = "good-key"


def _bearer_error(
    error: str | None,
    description: str | None = None,
    status: int = 401,
    scope: str | None = None,
) -> JSONResponse:
    challenge = "Bearer"
    params = []
    if error:
        params.append(f'error="{error}"')
    if description:
        params.append(f'error_description="{description}"')
    if scope:
        params.append(f'scope="{scope}"')
    if params:
        challenge += " " + ", ".join(params)
    body = {"error": "unauthorized" if status == 401 else "forbidden"}
    return JSONResponse(body, status_code=status, headers={"WWW-Authenticate": challenge})


def _authenticate(request: Request) -> dict | JSONResponse:
    """Return the token's claims, or the error response to send."""
    auth = request.headers.get("authorization")
    if auth is None:
        return _bearer_error(None)
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return _bearer_error("invalid_request", "expected 'Authorization: Bearer <token>'")
    if token == GOOD_TOKEN:
        return {"sub": "demo", "scope": "read"}
    try:
        return tokens.verify(token)
    except tokens.TokenError as exc:
        return _bearer_error("invalid_token", str(exc))


@app.get("/v1/me")
async def me(request: Request) -> JSONResponse:
    claims = _authenticate(request)
    if isinstance(claims, JSONResponse):
        return claims
    return JSONResponse({"user": claims["sub"]})


@app.get("/v1/admin/users")
async def admin_users(request: Request) -> JSONResponse:
    """Needs scope "admin". A valid token without it gets 403 insufficient_scope."""
    claims = _authenticate(request)
    if isinstance(claims, JSONResponse):
        return claims
    if "admin" not in claims.get("scope", "").split():
        return _bearer_error(
            "insufficient_scope", "requires admin scope", status=403, scope="admin"
        )
    return JSONResponse({"users": ["demo"]})


@app.get("/v1/keyed")
async def keyed(request: Request) -> JSONResponse:
    """API key in a header. Sending it as ?api_key= is the classic mistake."""
    key = request.headers.get("x-api-key")
    if key is None:
        return JSONResponse({"error": "missing X-API-Key header"}, status_code=401)
    if key != GOOD_API_KEY:
        return JSONResponse({"error": "invalid api key"}, status_code=401)
    return JSONResponse({"ok": True})


@app.get("/v1/old-me")
async def old_me(request: Request) -> RedirectResponse:
    """Redirect to /v1/me on a *different host name*.

    localhost and 127.0.0.1 reach the same server, but HTTP clients compare
    host names, so they treat this as a cross-origin redirect and drop the
    Authorization header. The client then gets a 401 from /v1/me.
    """
    host = request.url.hostname
    other = "127.0.0.1" if host == "localhost" else "localhost"
    port = request.url.port or 80
    return RedirectResponse(f"http://{other}:{port}/v1/me", status_code=302)


@app.post("/v1/items")
async def create_item(request: Request) -> JSONResponse:
    content_type = request.headers.get("content-type", "")
    if not content_type.lower().startswith("application/json"):
        return JSONResponse({"error": "unsupported media type"}, status_code=415)
    try:
        payload = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Deliberately vague: this is what real APIs often return.
        return JSONResponse({"error": "bad request"}, status_code=400)
    return JSONResponse({"created": payload}, status_code=201)


@app.post("/v1/old-items")
async def old_items() -> RedirectResponse:
    """Moved permanently. A 301 makes curl -L and httpx re-send the POST as a GET,
    without the body, so the client ends up with 405 Method Not Allowed."""
    return RedirectResponse("/v1/items", status_code=301)


class NewUser(BaseModel):
    email: str
    age: int


@app.post("/v1/users", status_code=201)
async def create_user(user: NewUser) -> dict:
    """FastAPI validates the body and returns 422 with per-field details."""
    return {"created": user.email}


# ---------------------------------------------------------------- misc -----


@app.get("/v1/report")
async def report(request: Request) -> JSONResponse:
    """Only produces JSON; asking for CSV gets 406."""
    accept = request.headers.get("accept", "*/*")
    if not any(t in accept for t in ("application/json", "*/*", "application/*")):
        return JSONResponse({"error": "not acceptable"}, status_code=406)
    return JSONResponse({"rows": []})


@app.get("/v1/limited")
async def limited() -> JSONResponse:
    return JSONResponse(
        {"error": "rate limit exceeded"},
        status_code=429,
        headers={"Retry-After": "30", "X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "0"},
    )


@app.get("/v1/quota")
async def quota() -> JSONResponse:
    """200 OK with an error inside: the status code lies."""
    return JSONResponse(
        {"ok": False, "error": {"code": "QUOTA_EXCEEDED", "message": "monthly quota used up"}}
    )


@app.get("/v1/search")
async def search(date_from: str | None = None) -> JSONResponse:
    """Vague 400: the real reason (date must be ISO 8601) is never stated.
    No rule can name it with confidence; this is where the LLM must earn its place."""
    if date_from is not None:
        try:
            date.fromisoformat(date_from)
        except ValueError:
            return JSONResponse({"error": "invalid parameter"}, status_code=400)
    return JSONResponse({"results": []})


@app.get("/v1/broken")
async def broken() -> JSONResponse:
    return JSONResponse({"error": "internal error"}, status_code=500)


@app.get("/v1/list")
async def list_things(page_size: int = 20) -> JSONResponse:
    """The reason is in the body, but as a plain string, not a field list."""
    if page_size > 100:
        return JSONResponse({"errors": "page_size must be <= 100"}, status_code=400)
    return JSONResponse({"items": [], "page_size": page_size})


@app.post("/v1/payments")
async def payments(request: Request) -> JSONResponse:
    """422 in a non-FastAPI error shape: details is a dict, not a list."""
    body = await request.json()
    if body.get("amount", 0) <= 0:
        return JSONResponse(
            {"message": "Validation failed", "details": {"amount": "must be positive"}},
            status_code=422,
        )
    return JSONResponse({"paid": body["amount"]}, status_code=201)


@app.get("/v1/legacy/me")
async def legacy_me(request: Request) -> JSONResponse:
    """An opaque (non-JWT) token that has expired. No WWW-Authenticate header;
    the only clue is the message. Rules can only say "token rejected"."""
    if request.headers.get("authorization") == "Bearer legacy-2fa81c":
        return JSONResponse({"message": "Signature has expired"}, status_code=401)
    return JSONResponse({"message": "Unauthorized"}, status_code=401)


@app.get("/v1/sso-report")
async def sso_report(request: Request):
    """Classic SSO trap: no session cookie, so the API redirects to a login
    page and curl -L ends on 200 OK... with an HTML sign-in form."""
    if "session=" not in request.headers.get("cookie", ""):
        return RedirectResponse("/login?next=/v1/sso-report", status_code=302)
    return JSONResponse({"report": []})


@app.get("/login")
async def login_page():
    from fastapi.responses import HTMLResponse

    return HTMLResponse(
        "<!doctype html><html><head><title>Sign in - Example SSO</title></head>"
        "<body><form method='post'><input name='user'><input name='password' type='password'>"
        "</form></body></html>"
    )


@app.get("/v1/session")
async def session() -> JSONResponse:
    """Sets a session cookie: a secret APIdoc has never seen, chosen by the server.
    Used to check that -vvv output and logs mask it anyway."""
    response = JSONResponse({"ok": True})
    response.set_cookie("sid", "srv-issued-cookie-9f8e7d6c5b4a", httponly=True)
    return response
