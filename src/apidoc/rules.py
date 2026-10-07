"""Deterministic diagnosis rules.

Each rule looks at the original request and the Trace and either returns a
Finding or None. Rules run on the *unredacted* data in memory (so they can
read a JWT's exp claim); everything they emit is redacted before it is shown
or sent anywhere.

Confidence is a ranking signal, not a probability. Rough scale:
  0.9+  the trace proves it (e.g. 429 with Retry-After)
  0.7   strong evidence, one plausible alternative
  0.5   a likely cause among several
  <0.4  a guess; the LLM should take over
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from apidoc import jwt
from apidoc.curl import ParsedCurl
from apidoc.diagnosis import Category, Diagnosis, Finding, Patch
from apidoc.models import Request
from apidoc.trace import Hop, Trace

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
KNOWN_SCHEMES = {"bearer", "basic", "digest", "token", "apikey", "negotiate", "aws4-hmac-sha256"}
API_KEY_PARAMS = {"api_key", "apikey", "api-key", "key", "access_key", "x-api-key"}
CLOCK_LEEWAY_S = 30


@dataclass
class Context:
    parsed: ParsedCurl
    trace: Trace
    now: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def request(self) -> Request:
        """The request as the user wrote it (before any redirect)."""
        return self.parsed.request

    @property
    def final(self) -> Hop | None:
        return self.trace.final


Rule = Callable[[Context], Finding | None]
RULES: list[Rule] = []


def rule(fn: Callable[[Context], Finding | None]) -> Rule:
    def wrapper(ctx: Context) -> Finding | None:
        finding = fn(ctx)
        return finding.model_copy(update={"rule": fn.__name__}) if finding else None

    wrapper.__name__ = fn.__name__
    RULES.append(wrapper)
    return wrapper


def _www_authenticate(hop: Hop) -> dict[str, str]:
    """Parse 'Bearer error="x", scope="y"' into {'scheme': 'Bearer', 'error': 'x', ...}."""
    value = hop.header("www-authenticate")
    if not value:
        return {}
    scheme, _, rest = value.partition(" ")
    params = dict(re.findall(r'(\w+)="([^"]*)"', rest))
    return {"scheme": scheme, **params}


def _ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _ago(seconds: float) -> str:
    seconds = abs(int(seconds))
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size:
            n = seconds // size
            return f"{n} {unit}{'s' if n != 1 else ''}"
    return f"{seconds} seconds"


def _looks_like_json(body: str | None) -> bool:
    return bool(body) and body.lstrip()[:1] in ("{", "[")


def _host(url: str) -> str:
    return urlsplit(url).netloc


def _snippet(text: str, limit: int = 200) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "..."


def _status_line(hop: Hop, n: int | None = None) -> str:
    where = f"hop {n} " if n is not None else ""
    return f"{where}response: {hop.status} {hop.reason}".strip()


@rule
def connection_failed(ctx: Context) -> Finding | None:
    if ctx.trace.error_kind != "connect":
        return None
    host = _host(ctx.request.url)
    return Finding(
        category=Category.CONNECTION,
        summary=f"Could not connect to {host}: nothing answered at that address.",
        evidence=[f"connection error: {ctx.trace.error}"],
        fix=(
            "Check the host and port for typos and that the server is running. "
            "For the mock API: `uvicorn mock_server.app:app --port 8000` "
            "(or `docker compose up --build`)."
        ),
        confidence=0.9,
    )


@rule
def tls_failed(ctx: Context) -> Finding | None:
    if ctx.trace.error_kind != "tls":
        return None
    error = ctx.trace.error or ""
    evidence = [f"TLS error: {error}"]
    if "WRONG_VERSION_NUMBER" in error or "record layer" in error:
        url = ctx.request.url.replace("https://", "http://", 1)
        return Finding(
            category=Category.TLS,
            summary="You used https:// but the server only speaks plain HTTP on that port.",
            evidence=evidence,
            fix="Use http:// for this server (or the port that serves HTTPS).",
            confidence=0.85,
            patch=Patch(url=url),
        )
    return Finding(
        category=Category.TLS,
        summary="The TLS handshake failed; the server's certificate was not trusted.",
        evidence=evidence,
        fix=(
            "Check the hostname matches the certificate. For a corporate proxy or self-signed "
            "certificate, point the client at the right CA bundle. Use -k only for local testing."
        ),
        confidence=0.75,
    )


@rule
def timed_out(ctx: Context) -> Finding | None:
    if ctx.trace.error_kind != "timeout":
        return None
    return Finding(
        category=Category.TIMEOUT,
        summary="The request timed out before the server answered.",
        evidence=[f"timeout: {ctx.trace.error}"],
        fix="Check the server is up and reachable (VPN, firewall); raise the timeout with -m.",
        confidence=0.8,
    )


@rule
def https_required(ctx: Context) -> Finding | None:
    final = ctx.final
    if not final or not ctx.request.url.startswith("http://"):
        return None
    if "plain http request was sent to https port" not in final.body.lower():
        return None
    return Finding(
        category=Category.TLS,
        summary="You sent plain HTTP to a port that expects HTTPS.",
        evidence=[_status_line(final), f"response body: {_snippet(final.body)}"],
        fix="Use https:// in the URL.",
        confidence=0.9,
        patch=Patch(url=ctx.request.url.replace("http://", "https://", 1)),
    )


@rule
def auth_dropped_on_redirect(ctx: Context) -> Finding | None:
    hops = ctx.trace.hops
    if len(hops) < 2:
        return None
    first, final = hops[0], hops[-1]
    if not first.request.has_header("authorization") or final.request.has_header("authorization"):
        return None
    if final.status not in (401, 403) or _host(first.request.url) == _host(final.request.url):
        return None
    scheme = (first.request.header("authorization") or "").split(" ", 1)[0]
    n = len(hops)
    return Finding(
        category=Category.AUTH_DROPPED_ON_REDIRECT,
        summary=(
            f"Your Authorization header was dropped when the redirect moved from "
            f"{_host(first.request.url)} to {_host(final.request.url)}, so the server "
            "never saw your token."
        ),
        evidence=[
            f"hop 1: {first.request.method} {first.request.url} sent Authorization ({scheme})",
            f"hop 1 response: {first.status} Location: {first.header('location')}",
            f"hop {n}: {final.request.method} {final.request.url} sent no Authorization header",
            _status_line(final, n),
        ],
        fix=(
            "HTTP clients (curl, httpx, browsers) strip Authorization on a redirect to a "
            "different host, so credentials are not leaked to it. Call the final URL "
            "directly with your token."
        ),
        confidence=0.95,
        patch=Patch(url=final.request.url),
    )


@rule
def method_changed_on_redirect(ctx: Context) -> Finding | None:
    hops = ctx.trace.hops
    final = ctx.final
    if not final or final.status < 400:
        return None
    for i, (hop, nxt) in enumerate(zip(hops, hops[1:], strict=False), start=1):
        if (
            hop.request.method in UNSAFE_METHODS
            and hop.status in (301, 302, 303)
            and nxt.request.method == "GET"
        ):
            return Finding(
                category=Category.METHOD_CHANGED_ON_REDIRECT,
                summary=(
                    f"The {hop.status} redirect turned your {hop.request.method} into a GET "
                    "and dropped the body."
                ),
                evidence=[
                    f"hop {i}: {hop.request.method} {hop.request.url} -> {hop.status}",
                    f"hop {i + 1}: GET {nxt.request.url} (no body)",
                    _status_line(final, len(hops)),
                ],
                fix=(
                    f"Clients follow 301/302/303 with GET by historical convention. Send the "
                    f"{hop.request.method} straight to the new URL (servers should use "
                    "307/308 to keep the method)."
                ),
                confidence=0.9,
                patch=Patch(url=nxt.request.url, method=hop.request.method),
            )
    return None


# ------------------------------------------------------------ auth ----------


def _has_credentials(req: Request) -> bool:
    if req.has_header("authorization") or req.has_header("cookie"):
        return True
    if any("key" in k.lower() or "token" in k.lower() for k, _ in req.headers):
        return True
    return any(k.lower() in API_KEY_PARAMS for k, _ in parse_qsl(urlsplit(req.url).query))


@rule
def api_key_in_query(ctx: Context) -> Finding | None:
    final = ctx.final
    if not final or final.status not in (401, 403):
        return None
    parts = urlsplit(ctx.request.url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    key_params = [(k, v) for k, v in params if k.lower() in API_KEY_PARAMS]
    if not key_params:
        return None
    name, value = key_params[0]
    mentioned = re.search(r"\b(x-[a-z-]*key|api-key)\b", final.body, re.IGNORECASE)
    header = mentioned.group(1) if mentioned else "X-API-Key"
    remaining = [(k, v) for k, v in params if (k, v) != (name, value)]
    new_url = urlunsplit(parts._replace(query=urlencode(remaining)))
    evidence = [f"request sent the key as query parameter ?{name}=", _status_line(final)]
    if mentioned:
        evidence.append(f"response body: {_snippet(final.body)}")
    return Finding(
        category=Category.API_KEY_LOCATION,
        summary=f"The API key went in the URL (?{name}=) but the API expects it in a header.",
        evidence=evidence,
        fix=(
            f"Send it as the `{header}` header instead. Keys in URLs also end up in server "
            "and proxy logs."
        ),
        confidence=0.85 if mentioned else 0.6,
        patch=Patch(url=new_url, set_headers=[(header, value)]),
    )


@rule
def auth_missing(ctx: Context) -> Finding | None:
    final = ctx.final
    if not final or final.status != 401 or _has_credentials(ctx.request):
        return None
    www = _www_authenticate(final)
    evidence = ["request had no Authorization header or API key", _status_line(final)]
    if final.header("www-authenticate"):
        evidence.append(f"WWW-Authenticate: {final.header('www-authenticate')}")
    mentioned = re.search(r"\b(x-[a-z-]*key|api-key)\b", final.body, re.IGNORECASE)
    if mentioned:
        header = mentioned.group(1)
        evidence.append(f"response body: {_snippet(final.body)}")
        return Finding(
            category=Category.AUTH_MISSING,
            summary=f"The request had no credentials; the API wants a `{header}` header.",
            evidence=evidence,
            fix=f"Add `-H '{header}: <your key>'`.",
            confidence=0.85,
            patch=Patch(set_headers=[(header, "<YOUR_API_KEY>")]),
        )
    scheme = www.get("scheme", "Bearer") or "Bearer"
    return Finding(
        category=Category.AUTH_MISSING,
        summary="The request had no credentials, so the server refused it.",
        evidence=evidence,
        fix=f"Add `-H 'Authorization: {scheme} <your token>'`.",
        confidence=0.85,
        patch=Patch(set_headers=[("Authorization", f"{scheme} <YOUR_TOKEN>")]),
    )


@rule
def auth_scheme_wrong(ctx: Context) -> Finding | None:
    final = ctx.final
    auth = ctx.request.header("authorization")
    if not final or not auth or final.status not in (400, 401):
        return None
    scheme, _, rest = auth.strip().partition(" ")
    if rest.lower().startswith("bearer "):
        return Finding(
            category=Category.AUTH_SCHEME,
            summary='The Authorization header says "Bearer" twice.',
            evidence=["Authorization header starts with 'Bearer Bearer'", _status_line(final)],
            fix="Remove the duplicate: `Authorization: Bearer <token>`.",
            confidence=0.85,
            patch=Patch(set_headers=[("Authorization", rest)]),
        )
    if rest and scheme.lower() in KNOWN_SCHEMES:
        return None
    return Finding(
        category=Category.AUTH_SCHEME,
        summary='The token was sent without an auth scheme: it needs "Bearer " in front.',
        evidence=[
            "Authorization header value has no scheme (expected 'Bearer <token>')",
            _status_line(final),
            *(
                [f"WWW-Authenticate: {final.header('www-authenticate')}"]
                if final.header("www-authenticate")
                else []
            ),
        ],
        fix="Use `Authorization: Bearer <token>`, not `Authorization: <token>`.",
        confidence=0.9,
        patch=Patch(set_headers=[("Authorization", f"Bearer {auth.strip()}")]),
    )


def _jwt_claims(ctx: Context) -> dict | None:
    token = jwt.bearer_token(ctx.request.header("authorization"))
    return jwt.claims(token) if token else None


@rule
def token_expired(ctx: Context) -> Finding | None:
    final = ctx.final
    claims = _jwt_claims(ctx)
    if not final or final.status not in (401, 403) or not claims or "exp" not in claims:
        return None
    now = ctx.now.timestamp()
    exp = float(claims["exp"])
    if exp >= now - CLOCK_LEEWAY_S:
        return None
    evidence = [f"token exp claim: {_ts(exp)} ({_ago(now - exp)} ago)", _status_line(final)]
    if final.header("www-authenticate"):
        evidence.append(f"WWW-Authenticate: {final.header('www-authenticate')}")
    lifetime = ""
    if "iat" in claims:
        lifetime = f" Tokens from this issuer last about {_ago(exp - float(claims['iat']))}."
    return Finding(
        category=Category.AUTH_EXPIRED,
        summary=f"Your token expired {_ago(now - exp)} ago.",
        evidence=evidence,
        fix=f"Get a new token (refresh it or log in again).{lifetime}",
        confidence=0.95,
    )


@rule
def token_not_yet_valid(ctx: Context) -> Finding | None:
    final = ctx.final
    claims = _jwt_claims(ctx)
    if not final or final.status not in (401, 403) or not claims:
        return None
    now = ctx.now.timestamp()
    nbf = float(claims.get("nbf", claims.get("iat", 0)))
    if nbf <= now + CLOCK_LEEWAY_S:
        return None
    evidence = [
        f"token nbf/iat claim: {_ts(nbf)}, {_ago(nbf - now)} in the future",
        f"this computer's clock: {_ts(now)}",
        _status_line(final),
    ]
    summary = f"Your token is not valid for another {_ago(nbf - now)}."
    server_date = final.header("date")
    if server_date:
        try:
            skew = now - parsedate_to_datetime(server_date).timestamp()
        except (TypeError, ValueError):
            skew = 0
        evidence.append(f"server Date header: {server_date}")
        if abs(skew) > 60:
            summary = f"Clock skew: your computer's clock is {_ago(skew)} off from the server's."
    return Finding(
        category=Category.AUTH_NOT_YET_VALID,
        summary=summary,
        evidence=evidence,
        fix=(
            "Sync the clock of whichever machine issued or is using the token (NTP), or wait. "
            "Tokens issued by a server whose clock runs fast are rejected until it catches up."
        ),
        confidence=0.85,
    )


@rule
def insufficient_scope(ctx: Context) -> Finding | None:
    final = ctx.final
    if not final or final.status != 403:
        return None
    www = _www_authenticate(final)
    claims = _jwt_claims(ctx) or {}
    have = claims.get("scope") or claims.get("scp")
    if www.get("error") == "insufficient_scope":
        need = www.get("scope", "?")
        evidence = [_status_line(final), f"WWW-Authenticate: {final.header('www-authenticate')}"]
        if have:
            evidence.append(f"token scope claim: {have}")
        return Finding(
            category=Category.AUTH_SCOPE,
            summary=f"Your token is valid but lacks the `{need}` scope this endpoint needs.",
            evidence=evidence,
            fix=f"Request a new token that includes the `{need}` scope.",
            confidence=0.95,
        )
    if ctx.request.has_header("authorization"):
        return Finding(
            category=Category.AUTH_SCOPE,
            summary="You are authenticated but not allowed to do this (403 Forbidden).",
            evidence=[_status_line(final), f"response body: {_snippet(final.body)}"],
            fix="Check the account's role or the token's scopes/permissions for this resource.",
            confidence=0.5,
        )
    return None


@rule
def token_rejected(ctx: Context) -> Finding | None:
    final = ctx.final
    if not final or final.status != 401 or not ctx.request.has_header("authorization"):
        return None
    www = _www_authenticate(final)
    evidence = [_status_line(final)]
    if final.header("www-authenticate"):
        evidence.append(f"WWW-Authenticate: {final.header('www-authenticate')}")
    detail = www.get("error_description")
    return Finding(
        category=Category.AUTH_INVALID,
        summary="The server rejected the token" + (f": {detail}." if detail else "."),
        evidence=evidence,
        fix=(
            "Check you copied the whole token, that it is for this environment (test vs live) "
            "and that it has not been revoked."
        ),
        confidence=0.7 if www.get("error") == "invalid_token" else 0.55,
    )


@rule
def json_sent_with_wrong_content_type(ctx: Context) -> Finding | None:
    final = ctx.final
    req = ctx.request
    if not final or final.status not in (400, 415) or not _looks_like_json(req.body):
        return None
    content_type = (req.header("content-type") or "").lower()
    if "json" in content_type:
        return None
    implicit = any(k.lower() == "content-type" for k, _ in ctx.parsed.implicit_headers)
    evidence = [
        f"request body starts with {req.body.lstrip()[:1]!r} (looks like JSON)",
        f"request Content-Type: {req.header('content-type') or '(none)'}",
        _status_line(final),
    ]
    if implicit:
        evidence.insert(2, "curl added that Content-Type itself because the command used -d")
    return Finding(
        category=Category.CONTENT_TYPE,
        summary=(
            "You sent JSON but labelled it as "
            f"{req.header('content-type') or 'nothing'}, so the server did not read it as JSON."
        ),
        evidence=evidence,
        fix="Add `-H 'Content-Type: application/json'` (or use `--json` instead of `-d`).",
        confidence=0.95 if final.status == 415 else 0.85,
        patch=Patch(set_headers=[("Content-Type", "application/json")]),
    )


_UNQUOTED_KEY = re.compile(r"[{,]\s*[A-Za-z_][A-Za-z0-9_]*\s*:")


@rule
def malformed_json(ctx: Context) -> Finding | None:
    final = ctx.final
    req = ctx.request
    if not final or final.status not in (400, 422) or not req.body:
        return None
    if "json" not in (req.header("content-type") or "").lower():
        return None
    try:
        json.loads(req.body)
        return None
    except json.JSONDecodeError as exc:
        error = f"{exc.msg} at line {exc.lineno} column {exc.colno}"
    evidence = [f"request body is not valid JSON: {error}", f"body: {_snippet(req.body, 120)}"]
    evidence.append(_status_line(final))
    fix = "Fix the JSON: keys and strings need double quotes, no trailing commas."
    if _UNQUOTED_KEY.search(req.body):
        fix += (
            " Unquoted keys usually mean the shell ate your double quotes: Windows "
            "PowerShell 5.1 strips them when calling curl.exe. Put the JSON in a file and "
            "use `--data-binary @body.json`, or use PowerShell 7."
        )
    return Finding(
        category=Category.MALFORMED_BODY,
        summary="The request body is not valid JSON.",
        evidence=evidence,
        fix=fix,
        confidence=0.9,
    )


@rule
def validation_failed(ctx: Context) -> Finding | None:
    final = ctx.final
    if not final or final.status not in (400, 422):
        return None
    body = final.json_body()
    if not isinstance(body, dict):
        return None
    items = body.get("detail") if isinstance(body.get("detail"), list) else body.get("errors")
    if not isinstance(items, list) or not items:
        return None
    problems = []
    for item in items[:5]:
        if isinstance(item, dict):
            loc = item.get("loc") or item.get("field") or item.get("path") or []
            loc = ".".join(str(p) for p in loc if p != "body") if isinstance(loc, list) else loc
            problems.append(f"{loc}: {item.get('msg') or item.get('message')}")
    if not problems:
        return None
    return Finding(
        category=Category.VALIDATION,
        summary="The server understood the request but rejected these fields: "
        + "; ".join(problems)
        + ".",
        evidence=[_status_line(final), *[f"validation error: {p}" for p in problems]],
        fix="Fix the listed fields in the request body and send it again.",
        confidence=0.85,
    )


@rule
def method_not_allowed(ctx: Context) -> Finding | None:
    final = ctx.final
    if not final or final.status != 405:
        return None
    allow = final.header("allow")
    evidence = [f"request method: {final.request.method}", _status_line(final)]
    patch = None
    if allow:
        evidence.append(f"Allow: {allow}")
        allowed = [m.strip().upper() for m in allow.split(",") if m.strip()]
        if allowed and final.request.method not in allowed:
            target = allowed[0]
            # Only offer a machine-applied fix we can stand behind: switching
            # GET -> POST without a body would just fail differently.
            if target not in UNSAFE_METHODS or final.request.body:
                patch = Patch(method=target)
    return Finding(
        category=Category.METHOD_NOT_ALLOWED,
        summary=f"This URL does not accept {final.request.method}"
        + (f"; it accepts {allow}." if allow else "."),
        evidence=evidence,
        fix="Use one of the allowed methods (`-X`), or check you have the right URL.",
        confidence=0.8,
        patch=patch,
    )


@rule
def not_found(ctx: Context) -> Finding | None:
    final = ctx.final
    if not final or final.status != 404:
        return None
    path = urlsplit(final.request.url).path
    return Finding(
        category=Category.NOT_FOUND,
        summary=f"The server has nothing at {path}.",
        evidence=[f"requested path: {path}", _status_line(final), f"body: {_snippet(final.body)}"],
        fix=(
            "Check the path for typos, a missing or wrong version prefix (/v1), a trailing "
            "slash, and that any ID in it exists."
        ),
        confidence=0.5,
    )


@rule
def not_acceptable(ctx: Context) -> Finding | None:
    final = ctx.final
    if not final or final.status != 406:
        return None
    accept = final.request.header("accept") or "(none)"
    return Finding(
        category=Category.NOT_ACCEPTABLE,
        summary=f"You asked for {accept}, which this endpoint cannot produce.",
        evidence=[f"request Accept: {accept}", _status_line(final)],
        fix="Ask for a format the API supports, usually `-H 'Accept: application/json'`.",
        confidence=0.85,
        patch=Patch(set_headers=[("Accept", "application/json")]),
    )


@rule
def vague_bad_request(ctx: Context) -> Finding | None:
    """Low confidence by design: the server gave no reason. The LLM's job."""
    final = ctx.final
    if not final or final.status != 400:
        return None
    params = [k for k, _ in parse_qsl(urlsplit(final.request.url).query)]
    evidence = [_status_line(final), f"response body: {_snippet(final.body)}"]
    if params:
        evidence.append(f"query parameters sent: {', '.join(params)}")
    return Finding(
        category=Category.BAD_PARAMETER,
        summary="The server rejected the request (400) without saying which part is wrong.",
        evidence=evidence,
        fix=(
            "Compare each parameter with the API docs: format (dates, IDs), required "
            "parameters and allowed values."
        ),
        confidence=0.3,
    )


@rule
def rate_limited(ctx: Context) -> Finding | None:
    final = ctx.final
    if not final or final.status != 429:
        return None
    evidence = [_status_line(final)]
    retry = final.header("retry-after")
    for name in ("retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"):
        if final.header(name):
            evidence.append(f"{name}: {final.header(name)}")
    wait = f"Wait {retry} seconds" if retry and retry.isdigit() else "Wait"
    return Finding(
        category=Category.RATE_LIMITED,
        summary="You hit the API's rate limit.",
        evidence=evidence,
        fix=f"{wait}, then retry; in code, back off exponentially and honour Retry-After.",
        confidence=0.95,
    )


@rule
def error_in_success(ctx: Context) -> Finding | None:
    final = ctx.final
    if not final or not 200 <= final.status < 300:
        return None
    body = final.json_body()
    if not isinstance(body, dict):
        return None
    failed = body.get("ok") is False or body.get("success") is False
    error = body.get("error") or body.get("errors")
    if not (failed or error):
        return None
    return Finding(
        category=Category.ERROR_IN_SUCCESS,
        summary="The status says 200 OK, but the body reports an error.",
        evidence=[_status_line(final), f"response body: {_snippet(json.dumps(body))}"],
        fix=(
            "This API reports errors inside the body; read the error field. Code that only "
            "checks the status code will miss this."
        ),
        confidence=0.85,
    )


@rule
def server_error(ctx: Context) -> Finding | None:
    final = ctx.final
    if not final or final.status < 500:
        return None
    gateway = final.status in (502, 503, 504)
    return Finding(
        category=Category.SERVER_ERROR,
        summary=(
            "A gateway or proxy in front of the API failed."
            if gateway
            else "The server crashed while handling the request."
        ),
        evidence=[_status_line(final), f"response body: {_snippet(final.body)}"],
        fix=(
            "Usually not your request's fault: retry later, check the API's status page. If "
            "it fails only for this input, report it with the request ID if one is returned."
        ),
        confidence=0.75,
    )


def run_rules(ctx: Context) -> list[Finding]:
    findings = [f for r in RULES if (f := r(ctx)) is not None]
    return sorted(findings, key=lambda f: f.confidence, reverse=True)


def diagnose_with_rules(ctx: Context) -> Diagnosis:
    findings = run_rules(ctx)
    final = ctx.final
    if findings:
        top = findings[0]
        return Diagnosis(
            category=top.category,
            summary=top.summary,
            evidence=top.evidence,
            fix=top.fix,
            confidence=top.confidence,
            source="rules",
            fixed_request=top.patch.apply(ctx.request) if top.patch else None,
            findings=findings,
        )
    if final and final.status < 400:
        # A success is only trusted when nothing about it looks off. An API that
        # answers with HTML, or only after a redirect, may have sent you to a
        # login page with 200 OK (the eval's h05), so that stays low and "auto"
        # asks the LLM. A plain JSON 200 does not cost an LLM call.
        html = "html" in (final.header("content-type") or "").lower()
        redirected = len(ctx.trace.hops) > 1
        suspicious = html or redirected
        evidence = [_status_line(final)]
        if html:
            evidence.append(f"response Content-Type: {final.header('content-type')}")
        if redirected:
            evidence.append(f"reached after {len(ctx.trace.hops) - 1} redirect(s)")
        return Diagnosis(
            category=Category.OK,
            summary=f"The request succeeded ({final.status} {final.reason}).",
            evidence=evidence,
            fix="Nothing to fix.",
            confidence=0.5 if suspicious else 0.9,
        )
    status = f"{final.status} {final.reason}" if final else ctx.trace.error_kind or "no response"
    evidence = [f"final status: {status}"]
    if final:
        evidence.append(f"response body: {_snippet(final.body)}")
    return Diagnosis(
        category=Category.UNKNOWN,
        summary=f"The request failed ({status}) and no rule recognised the cause.",
        evidence=evidence,
        fix="Read the response body and the API's docs for this status code.",
        confidence=0.1,
    )
