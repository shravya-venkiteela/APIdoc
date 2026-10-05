from __future__ import annotations

import time

import httpx

from apidoc import __version__
from apidoc.curl import ParsedCurl
from apidoc.models import Request
from apidoc.trace import Hop, Trace

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
DEFAULT_TIMEOUT = 30.0
MAX_BODY_CHARS = 64_000


class UnsafeRequestError(RuntimeError):
    def __init__(self, method: str) -> None:
        super().__init__(
            f"{method} is not a safe method: re-running it could change data on the server "
            "(create, charge, delete). Pass --allow-unsafe to run it anyway, or analyse a "
            "saved trace with --trace-file."
        )
        self.method = method


def run(
    parsed: ParsedCurl,
    *,
    allow_unsafe: bool = False,
    transport: httpx.BaseTransport | None = None,
    max_body_chars: int = MAX_BODY_CHARS,
) -> Trace:
    req = parsed.request
    if req.method.upper() not in SAFE_METHODS and not allow_unsafe:
        raise UnsafeRequestError(req.method.upper())

    headers = list(req.headers)
    # httpx would otherwise send "python-httpx/x"; say who we are instead.
    if not req.has_header("user-agent"):
        headers.append(("User-Agent", f"apidoc/{__version__}"))

    trace = Trace(follow_redirects=parsed.follow_redirects)
    start = time.perf_counter()
    try:
        with httpx.Client(
            follow_redirects=parsed.follow_redirects,
            verify=parsed.verify_tls,
            timeout=parsed.timeout or DEFAULT_TIMEOUT,
            transport=transport,
            max_redirects=20,
        ) as client:
            response = client.request(
                req.method,
                req.url,
                headers=headers,
                content=req.body.encode() if req.body is not None else None,
            )
            for r in [*response.history, response]:
                trace.hops.append(_hop(r, max_body_chars))
    except httpx.TooManyRedirects as exc:
        trace.error, trace.error_kind = str(exc), "too_many_redirects"
    except httpx.TimeoutException as exc:
        trace.error, trace.error_kind = f"{type(exc).__name__}: {exc}", "timeout"
    except httpx.ConnectError as exc:
        message = str(exc)
        kind = "tls" if any(s in message for s in ("SSL", "CERTIFICATE", "TLS")) else "connect"
        trace.error, trace.error_kind = message, kind
    except httpx.HTTPError as exc:
        trace.error, trace.error_kind = f"{type(exc).__name__}: {exc}", "http"
    trace.total_ms = (time.perf_counter() - start) * 1000
    return trace


def _hop(response: httpx.Response, max_body_chars: int) -> Hop:
    sent = response.request
    try:
        content = sent.content
    except httpx.RequestNotRead:
        # httpx builds redirect requests with a lazy body stream it never buffers.
        try:
            content = sent.read()
        except (httpx.StreamError, RuntimeError):
            content = b""
    sent_body = content.decode(errors="replace") if content else None
    try:
        text = response.text
    except httpx.ResponseNotRead:
        text = ""
    return Hop(
        request=Request(
            method=sent.method,
            url=str(sent.url),
            headers=list(sent.headers.multi_items()),
            body=sent_body,
        ),
        status=response.status_code,
        reason=response.reason_phrase,
        http_version=response.http_version,
        headers=list(response.headers.multi_items()),
        body=text[:max_body_chars],
        body_truncated=len(text) > max_body_chars,
        elapsed_ms=response.elapsed.total_seconds() * 1000,
    )
