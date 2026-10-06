from __future__ import annotations

import base64
import re
import shlex
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from pydantic import BaseModel, Field

from apidoc.models import Request
from apidoc.redact import SENSITIVE_HEADERS, SENSITIVE_KEY, Redactor


class CurlParseError(ValueError):
    pass


class ParsedCurl(BaseModel):
    request: Request
    follow_redirects: bool = False
    verify_tls: bool = True
    timeout: float | None = None
    # Headers curl adds on its own, e.g. the form Content-Type for -d.
    implicit_headers: list[tuple[str, str]] = Field(default_factory=list)
    # Flags we recognised but ignore, and flags we did not recognise.
    warnings: list[str] = Field(default_factory=list)
    # Credential values found in the command, for the Redactor.
    secrets: list[str] = Field(default_factory=list)

    def redactor(self) -> Redactor:
        return Redactor(self.secrets)


# Flags that take a value and only affect output or transport details we
# do not reproduce. Parsed so their value is not mistaken for the URL.
_IGNORED_WITH_VALUE = {
    "-o", "--output", "-w", "--write-out", "--retry", "--limit-rate",
    "-c", "--cookie-jar", "--cacert", "--cert", "--key", "-E",
}  # fmt: skip
_IGNORED_FLAGS = {
    "-s", "--silent", "-S", "--show-error", "-v", "--verbose", "-i", "--include",
    "--compressed", "-f", "--fail", "-#", "--progress-bar", "-N", "--no-buffer",
    "--http1.1", "--http2",
}  # fmt: skip
_DATA_FLAGS = {"-d", "--data", "--data-raw", "--data-binary", "--data-ascii"}


def _normalise(command: str) -> str:
    """Join line continuations from bash (\\), cmd.exe (^) and PowerShell (`).

    Only outside quotes: inside '...' a backslash-newline is literal body text,
    as in bash. (Inside "..." bash removes it, so we do too.)
    """
    out: list[str] = []
    quote_char = ""
    i = 0
    while i < len(command):
        ch = command[i]
        nl = re.match(r"\r?\n", command[i + 1 :]) if ch in "\\^`" else None
        if nl and quote_char != "'" and not (quote_char == '"' and ch != "\\"):
            out.append("" if quote_char else " ")
            i += 1 + len(nl.group())
            continue
        if ch == "\\" and quote_char != "'" and i + 1 < len(command):
            out.append(command[i : i + 2])  # an escaped character is never a quote
            i += 2
            continue
        if ch in "'\"" and quote_char in ("", ch):
            quote_char = "" if quote_char else ch
        out.append(ch)
        i += 1
    return "".join(out).strip()


def parse_curl(command: str) -> ParsedCurl:
    try:
        tokens = shlex.split(_normalise(command), posix=True)
    except ValueError as exc:  # unbalanced quotes
        raise CurlParseError(f"could not split command: {exc}") from exc
    if tokens and tokens[0].lower() in {"curl", "curl.exe"}:
        tokens = tokens[1:]
    if not tokens:
        raise CurlParseError("empty curl command")

    method: str | None = None
    url: str | None = None
    headers: list[tuple[str, str]] = []
    data: list[str] = []
    json_body = False
    get_mode = head_mode = False
    out = ParsedCurl(request=Request(url="http://placeholder"))

    i = 0

    def value() -> str:
        nonlocal i
        i += 1
        if i >= len(tokens):
            raise CurlParseError(f"{tokens[i - 1]} needs a value")
        return tokens[i]

    while i < len(tokens):
        tok = tokens[i]
        # Allow -XPOST and -HHeader:value forms.
        if re.fullmatch(r"-[XHdub]\S+", tok) and not tok.startswith("--"):
            tokens[i : i + 1] = [tok[:2], tok[2:]]
            tok = tokens[i]

        if tok in ("-X", "--request"):
            method = value().upper()
        elif tok in ("-H", "--header"):
            name, sep, val = value().partition(":")
            if not sep:
                out.warnings.append(f"ignored malformed header {name!r}")
            else:
                headers.append((name.strip(), val.strip()))
        elif tok in _DATA_FLAGS:
            raw = value()
            if raw.startswith("@") and tok != "--data-raw":
                raw = _read_data_file(raw[1:], keep_newlines=tok == "--data-binary")
            data.append(raw)
        elif tok == "--data-urlencode":
            raw = value()
            name, sep, val = raw.partition("=")
            data.append(f"{name}={quote(val, safe='')}" if sep else quote(raw, safe=""))
        elif tok == "--json":
            data.append(value())
            json_body = True
        elif tok in ("-u", "--user"):
            user, _, password = value().partition(":")
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            headers.append(("Authorization", f"Basic {token}"))
            out.secrets += [password, f"{user}:{password}", token]
        elif tok in ("-b", "--cookie"):
            headers.append(("Cookie", value()))
        elif tok in ("-A", "--user-agent"):
            headers.append(("User-Agent", value()))
        elif tok in ("-e", "--referer"):
            headers.append(("Referer", value()))
        elif tok in ("-L", "--location"):
            out.follow_redirects = True
        elif tok in ("-k", "--insecure"):
            out.verify_tls = False
        elif tok in ("-G", "--get"):
            get_mode = True
        elif tok in ("-I", "--head"):
            head_mode = True
        elif tok in ("-m", "--max-time"):
            out.timeout = float(value())
        elif tok == "--url":
            url = value()
        elif tok in ("-F", "--form"):
            value()
            out.warnings.append("-F/--form (multipart) is not supported yet; body dropped")
        elif tok in _IGNORED_FLAGS:
            pass
        elif tok in _IGNORED_WITH_VALUE:
            value()
        elif tok.startswith("-") and len(tok) > 1:
            out.warnings.append(f"unknown flag {tok} ignored")
        else:
            if url is not None:
                out.warnings.append(f"extra argument {tok!r} ignored (only one URL supported)")
            else:
                url = tok
        i += 1

    if url is None:
        raise CurlParseError("no URL found in curl command")
    if "://" not in url:
        url = "http://" + url  # curl's default

    body: str | None = "&".join(data) if data else None

    if get_mode and body is not None:
        url = _append_query(url, body)
        body = None

    if head_mode:
        method = method or "HEAD"
    elif method is None:
        method = "POST" if body is not None else "GET"

    def add_implicit(name: str, val: str) -> None:
        if not any(k.lower() == name.lower() for k, _ in headers):
            headers.append((name, val))
            out.implicit_headers.append((name, val))

    if json_body:
        add_implicit("Content-Type", "application/json")
        add_implicit("Accept", "application/json")
    elif body is not None:
        add_implicit("Content-Type", "application/x-www-form-urlencoded")

    out.request = Request(method=method, url=url, headers=headers, body=body)
    out.secrets += _credentials(out.request)
    out.secrets = sorted({s for s in out.secrets if s})
    return out


def _read_data_file(path: str, *, keep_newlines: bool) -> str:
    """curl -d @file reads the body from a file and, unlike --data-binary,
    strips carriage returns and newlines."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise CurlParseError(f"cannot read data file {path!r}: {exc.strerror}") from exc
    return text if keep_newlines else text.replace("\r", "").replace("\n", "")


def _append_query(url: str, extra: str) -> str:
    parts = urlsplit(url)
    query = f"{parts.query}&{extra}" if parts.query else extra
    return urlunsplit(parts._replace(query=query))


def _credentials(req: Request) -> list[str]:
    """Pull credential values out of a request so the Redactor knows them."""
    found: list[str] = []
    for name, val in req.headers:
        if name.lower() in SENSITIVE_HEADERS:
            # "Bearer abc" -> also register "abc" on its own.
            found.append(val)
            found.append(val.split(None, 1)[-1])
            if name.lower() == "cookie":
                found += [p.partition("=")[2] for p in val.split(";")]
    parts = urlsplit(req.url)
    found += [v for k, v in parse_qsl(parts.query) if SENSITIVE_KEY.search(k)]
    if parts.password:
        found.append(parts.password)
    if req.body and "=" in req.body and not req.body.lstrip().startswith(("{", "[")):
        found += [v for k, v in parse_qsl(req.body) if SENSITIVE_KEY.search(k)]
    return [f.strip() for f in found]
