"""Re-run a request and record a Trace.

Safety first: re-running a request the user pasted is not free. A failing
`POST /charges` or `DELETE /repos/x` might have half-succeeded, and running
it again could charge a card twice. So only safe methods (RFC 9110 sec. 9.2.1)
run by default; anything else needs an explicit allow_unsafe=True, which the
CLI exposes as --allow-unsafe. The alternative is to analyse a saved trace.
"""

from __future__ import annotations

import logging
import re
import time
from urllib.parse import urlsplit

import httpx

from apidoc import __version__
from apidoc.curl import ParsedCurl
from apidoc.logs import TRACE
from apidoc.models import Request
from apidoc.redact import Redactor
from apidoc.trace import Hop, Trace

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
DEFAULT_TIMEOUT = 30.0
MAX_BODY_CHARS = 64_000

log = logging.getLogger("apidoc.runner")
# Masks sensitive headers by *name* (Authorization, Cookie, Set-Cookie, ...),
# including values no one has seen before, such as a cookie the server sets.
_BY_NAME = Redactor()


class UnsafeRequestError(RuntimeError):
    def __init__(self, method: str) -> None:
        super().__init__(
            f"{method} is not a safe method: re-running it could change data on the server "
            "(create, charge, delete). Pass --allow-unsafe to run it anyway, or analyse a "
            "saved trace with --trace-file."
        )
        self.method = method


_REFUSED = re.compile(r"refused|errno 111|errno 61|10061", re.I)
_NO_SUCH_HOST = re.compile(
    r"getaddrinfo|name or service not known|nodename nor servname|11001|no address", re.I
)


def _portable(message: str, url: str) -> str:
    """The same failure reads differently per OS ("[WinError 10061] No connection
    could be made..." vs "[Errno 111] Connection refused"). Say it one way, so the
    evidence, the LLM prompt and the eval are identical everywhere; keep the raw
    text in the debug log."""
    log.debug("raw connect error: %s", message)
    netloc = urlsplit(url).netloc
    if _REFUSED.search(message):
        return f"connection refused: nothing is listening at {netloc}"
    if _NO_SUCH_HOST.search(message):
        return f"name resolution failed: {urlsplit(url).hostname} could not be resolved"
    return message


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
    log.info(
        "re-running %s %s",
        req.method,
        req.url,
        extra={"x_event": "request", "x_method": req.method, "x_url": req.url},
    )
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
                _log_hop(len(trace.hops), trace.hops[-1])
    except httpx.TooManyRedirects as exc:
        trace.error, trace.error_kind = str(exc), "too_many_redirects"
    except httpx.TimeoutException as exc:
        trace.error, trace.error_kind = f"{type(exc).__name__}: {exc}", "timeout"
    except httpx.ConnectError as exc:
        message = str(exc)
        kind = "tls" if any(s in message for s in ("SSL", "CERTIFICATE", "TLS")) else "connect"
        if kind == "connect":
            message = _portable(message, req.url)
        trace.error, trace.error_kind = message, kind
    except httpx.HTTPError as exc:
        trace.error, trace.error_kind = f"{type(exc).__name__}: {exc}", "http"
    trace.total_ms = (time.perf_counter() - start) * 1000
    if trace.error:
        log.warning("no response: %s: %s", trace.error_kind, trace.error)
    log.info("done in %.0f ms, %d hop(s)", trace.total_ms, len(trace.hops))
    return trace


def _log_hop(n: int, hop: Hop) -> None:
    log.debug(
        "hop %d: %s %s -> %d %s (%.0f ms)",
        n,
        hop.request.method,
        hop.request.url,
        hop.status,
        hop.reason,
        hop.elapsed_ms,
        extra={
            "x_event": "hop",
            "x_hop": n,
            "x_status": hop.status,
            "x_elapsed_ms": round(hop.elapsed_ms, 1),
        },
    )
    # TRACE: all headers. Masked by name here, then by value in the log filter.
    for label, headers in (("request", hop.request.headers), ("response", hop.headers)):
        for name, value in _BY_NAME.headers(headers):
            log.log(TRACE, "hop %d %s header %s: %s", n, label, name, value)


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
