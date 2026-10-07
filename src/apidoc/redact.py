"""Secret redaction.

Every string that leaves APIdoc (log lines, terminal output, saved traces,
the prompt sent to the LLM) goes through a Redactor first.

Two layers, because neither is enough alone:

1. Known values: secrets APIdoc has seen (from the curl command, a profile or
   the keyring) are replaced wherever they appear, in any encoding we can
   predict (raw, URL-encoded, base64).
2. Patterns: things that look like secrets even if we never saw them before
   (JWTs, "Bearer ..." values, provider key prefixes, sensitive query params
   and JSON keys, passwords in URLs).
"""

from __future__ import annotations

import base64
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import quote, quote_plus

MASK = "[REDACTED]"

# Headers whose whole value is a credential.
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-amz-security-token",
    "private-token",
}

# Names that mark a value as secret in query strings, form bodies and JSON.
# Deliberately NOT included: "code" (error codes are key evidence; the OAuth
# authorization code is caught by the query-string pattern) and bare "auth"
# substrings (would hit "author", "authority").
SENSITIVE_KEY = re.compile(
    r"(pass(word|wd)?|secret|token|api[-_]?key|apikey|^key$|^auth$|authorization|"
    r"credential|session|^sig$|signature|code_verifier|private[-_]?key)",
    re.IGNORECASE,
)

# Auth schemes whose name we keep, so the diagnosis can still say "Bearer".
_SCHEME_VALUE = re.compile(r"^\s*(Bearer|Basic|Token|Digest|ApiKey)\s+(.+)$", re.IGNORECASE)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # JWT: three base64url segments, first one starts with eyJ ('{"').
    (re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), MASK),
    # Provider prefixes: GitHub, Slack, Google, AWS, Stripe, OpenAI/Anthropic-style.
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"), MASK),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), MASK),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), MASK),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),
    (re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{10,}"), MASK),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), MASK),
    # A credential header written out as text, e.g. in a curl -H argument or a log line.
    (
        re.compile(
            r"((?:proxy-)?authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|"
            r"private-token)(\s*:\s*)((?:Bearer|Basic|Token|Digest|ApiKey)\s+)?[^\s'\"]+",
            re.IGNORECASE,
        ),
        rf"\1\2\3{MASK}",
    ),
    # "Bearer <value>" / "Basic <value>" elsewhere in free text. Case-sensitive and
    # 8+ characters, so prose like "the bearer token" is left alone.
    (re.compile(r"\b(Bearer|Basic)\s+(?!\[REDACTED\])[A-Za-z0-9._~+/=-]{8,}"), rf"\1 {MASK}"),
    # Password in a URL: scheme://user:password@host
    (re.compile(r"([a-z][a-z0-9+.-]*://[^/\s:@]+):[^/\s@]+@", re.IGNORECASE), rf"\1:{MASK}@"),
    # curl -u user:password / --user user:password
    (re.compile(r"(\s(?:-u|--user)\s+['\"]?[^\s:'\"]+):[^\s'\"]+"), rf"\1:{MASK}"),
    # key=value in query strings, form bodies and Cookie headers.
    (
        re.compile(
            r"([?&;\s]|^)([A-Za-z0-9_.-]*(?:pass(?:word|wd)?|secret|token|api[-_]?key|apikey|"
            r"session|signature|code_verifier)[A-Za-z0-9_.-]*|key|sig|code|auth)=([^&;\s'\"]+)",
            re.IGNORECASE,
        ),
        rf"\1\2={MASK}",
    ),
    # "key": "value" in JSON text that we could not parse as JSON.
    (
        re.compile(
            r'("[A-Za-z0-9_.-]*(?:pass(?:word|wd)?|secret|token|api[-_]?key|apikey|'
            r'credential|private[-_]?key)[A-Za-z0-9_.-]*"\s*:\s*)"[^"]*"',
            re.IGNORECASE,
        ),
        rf'\1"{MASK}"',
    ),
]

MIN_SECRET_LEN = 4


class Redactor:
    """Masks known secret values and secret-looking patterns."""

    def __init__(self, known: Iterable[str] = ()) -> None:
        self._known: set[str] = set()
        for value in known:
            self.add(value)

    def add(self, secret: str | None) -> None:
        """Register a secret value, plus the encodings it may appear in."""
        if not secret or len(secret) < MIN_SECRET_LEN:
            return
        variants = {
            secret,
            quote(secret, safe=""),
            quote_plus(secret),
            base64.b64encode(secret.encode()).decode(),
            base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
        }
        self._known.update(v for v in variants if len(v) >= MIN_SECRET_LEN)

    def add_basic_auth(self, user: str, password: str) -> None:
        """Basic auth sends base64(user:password), which contains neither part verbatim."""
        self.add(password)
        self.add(f"{user}:{password}")

    @property
    def known_count(self) -> int:
        return len(self._known)

    # ---- strings -----------------------------------------------------------

    def text(self, value: str) -> str:
        if not value:
            return value
        # Longest first, so a secret is not half-masked by a shorter one inside it.
        for secret in sorted(self._known, key=len, reverse=True):
            if secret in value:
                value = value.replace(secret, MASK)
        for pattern, replacement in _PATTERNS:
            value = pattern.sub(replacement, value)
        return value

    # structured data

    def header_value(self, name: str, value: str) -> str:
        if name.lower() in SENSITIVE_HEADERS:
            if name.lower() in {"cookie", "set-cookie"}:
                return self._cookie(name, value)
            match = _SCHEME_VALUE.match(value)
            if match:
                return f"{match.group(1)} {MASK}"
            return MASK
        return self.text(value)

    def headers(
        self, headers: Mapping[str, str] | Iterable[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        items = headers.items() if isinstance(headers, Mapping) else headers
        return [(k, self.header_value(k, v)) for k, v in items]

    def json(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            return {
                k: (
                    MASK
                    if isinstance(k, str) and SENSITIVE_KEY.search(k) and v not in (None, "")
                    else self.json(v)
                )
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [self.json(v) for v in obj]
        if isinstance(obj, str):
            return self.text(obj)
        return obj

    @staticmethod
    def _cookie(name: str, value: str) -> str:
        """Keep cookie names (useful evidence), mask cookie values.

        Cookie (request):     "a=1; b=2"            every pair is a cookie.
        Set-Cookie (response): "a=1; Path=/; Secure" only the first pair is;
                                                    the rest are attributes.
        """
        parts = [p.strip() for p in value.split(";")]

        def mask(pair: str) -> str:
            key, eq, _ = pair.partition("=")
            return f"{key}={MASK}" if eq else pair

        if name.lower() == "cookie":
            return "; ".join(mask(p) for p in parts)
        return "; ".join([mask(parts[0]), *parts[1:]])
