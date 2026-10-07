"""Endpoints for the held-out eval set (evals/heldout.json).

Written and committed before any LLM was run against them, and no rule in
APIdoc was written for them. Each fails in one realistic way that APIs in the
wild really use; the clue to the cause is in the response, not in a rule.
"""

from __future__ import annotations

import json
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()

ORDER_STATUSES = {"pending", "shipped", "delivered"}
API_VERSIONS = "2024-06-01, 2025-01-01"
CATALOG_PAGES = 3


@router.get("/v1/orders")
async def orders(status: str | None = None) -> JSONResponse:
    """Enum values are case-sensitive; the error does not say so."""
    if status is not None and status not in ORDER_STATUSES:
        return JSONResponse({"error": "invalid value"}, status_code=400)
    return JSONResponse({"orders": []})


@router.post("/graphql")
async def graphql(request: Request) -> JSONResponse:
    """GraphQL reports errors with 200 OK and an `errors` array."""
    query = json.loads(await request.body() or b"{}").get("query", "")
    if "emial" in query:
        message = 'Cannot query field "emial" on type "User". Did you mean "email"?'
        return JSONResponse({"data": None, "errors": [{"message": message}]})
    return JSONResponse({"data": {"user": {"name": "Ann", "email": "ann@example.com"}}})


@router.get("/v1/reports")
async def reports(request: Request) -> JSONResponse:
    """A revoked key: the body is generic, the reason is only in a header."""
    key = request.headers.get("x-api-key")
    if key is None:
        return JSONResponse({"error": "missing api key"}, status_code=401)
    if key != "good-key":
        return JSONResponse(
            {"error": "forbidden"}, status_code=403, headers={"X-Error-Reason": "api key revoked"}
        )
    return JSONResponse({"reports": []})


@router.get("/v1/catalog")
async def catalog(page: int = 1) -> JSONResponse:
    """Paging past the end gives a bare 404; the page count is in a header."""
    headers = {"X-Total-Pages": str(CATALOG_PAGES)}
    if page > CATALOG_PAGES:
        return JSONResponse({"error": "not found"}, status_code=404, headers=headers)
    return JSONResponse({"page": page, "items": []}, headers=headers)


@router.get("/v1/billing")
async def billing(request: Request) -> JSONResponse:
    """Requires an Api-Version header; the 400 body does not say which."""
    if request.headers.get("api-version") not in API_VERSIONS.split(", "):
        return JSONResponse(
            {"error": "unsupported request"},
            status_code=400,
            headers={"Supported-Api-Versions": API_VERSIONS},
        )
    return JSONResponse({"invoices": []})


@router.post("/v1/charges")
async def charges(request: Request) -> JSONResponse:
    """Payment APIs often require an Idempotency-Key on every POST."""
    if "idempotency-key" not in request.headers:
        return JSONResponse({"error": "missing_idempotency_key"}, status_code=428)
    return JSONResponse({"charged": True}, status_code=201)


@router.get("/v1/account")
async def account(request: Request) -> JSONResponse:
    """Bearer-only API: Basic credentials (curl -u) are rejected with a challenge."""
    if request.headers.get("authorization") == "Bearer good-token":
        return JSONResponse({"account": "demo"})
    return JSONResponse(
        {"error": "unauthorized"},
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer realm="api"'},
    )


@router.get("/v1/files/report.csv")
async def signed_file(request: Request) -> JSONResponse:
    """A pre-signed URL past its expiry time."""
    expires = request.query_params.get("X-Expires", "0")
    if not expires.isdigit() or int(expires) < time.time():
        return JSONResponse({"error": "Request has expired"}, status_code=403)
    return JSONResponse({"csv": "a,b\n1,2\n"})


@router.get("/v1/repos")
async def repos(request: Request) -> JSONResponse:
    """GitHub-style: rate limiting answered with 403, not 429."""
    return JSONResponse(
        {"message": "API rate limit exceeded for user."},
        status_code=403,
        headers={
            "X-RateLimit-Limit": "60",
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": "1767225600",
        },
    )


@router.get("/v1/profile")
async def profile(request: Request) -> JSONResponse:
    """Only the standard header name counts."""
    if request.headers.get("authorization") == "Bearer good-token":
        return JSONResponse({"profile": "demo"})
    return JSONResponse(
        {"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"}
    )
