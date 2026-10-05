from __future__ import annotations

import json

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse

app = FastAPI(title="APIdoc mock API")

GOOD_TOKEN = "good-token"


def _bearer_error(error: str | None, description: str | None = None) -> JSONResponse:
    challenge = "Bearer"
    if error:
        challenge += f' error="{error}"'
        if description:
            challenge += f', error_description="{description}"'
    return JSONResponse(
        {"error": "unauthorized"},
        status_code=401,
        headers={"WWW-Authenticate": challenge},
    )


@app.get("/v1/me")
async def me(request: Request) -> JSONResponse:
    auth = request.headers.get("authorization")
    if auth is None:
        return _bearer_error(None)
    if auth != f"Bearer {GOOD_TOKEN}":
        return _bearer_error("invalid_token")
    return JSONResponse({"user": "demo"})


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


@app.post("/v1/old-items")
async def old_items() -> RedirectResponse:
    """Moved permanently. A 301 makes curl -L and httpx re-send the POST as a GET,
    without the body, so the client ends up with 405 Method Not Allowed."""
    return RedirectResponse("/v1/items", status_code=301)
