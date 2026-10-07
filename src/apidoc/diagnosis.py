"""The typed output of APIdoc: what went wrong, the evidence, and the fix.

Both the rules engine and the LLM produce the same Diagnosis type. That is
deliberate: the eval compares them like-for-like, and the CLI renders either
without caring where it came from.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from apidoc.models import Request
from apidoc.redact import Redactor


class Category(StrEnum):
    # authentication / authorisation
    AUTH_MISSING = "auth_missing"
    AUTH_SCHEME = "auth_scheme"  # e.g. token sent without "Bearer "
    AUTH_INVALID = "auth_invalid"
    AUTH_EXPIRED = "auth_expired"
    AUTH_NOT_YET_VALID = "auth_not_yet_valid"  # usually clock skew
    AUTH_SCOPE = "auth_scope"
    AUTH_DROPPED_ON_REDIRECT = "auth_dropped_on_redirect"
    API_KEY_LOCATION = "api_key_location"
    # request shape
    CONTENT_TYPE = "content_type"
    MALFORMED_BODY = "malformed_body"
    VALIDATION = "validation"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    METHOD_CHANGED_ON_REDIRECT = "method_changed_on_redirect"
    NOT_FOUND = "not_found"
    NOT_ACCEPTABLE = "not_acceptable"
    BAD_PARAMETER = "bad_parameter"
    # server / transport
    RATE_LIMITED = "rate_limited"
    ERROR_IN_SUCCESS = "error_in_success"
    SERVER_ERROR = "server_error"
    CONNECTION = "connection"
    TLS = "tls"
    TIMEOUT = "timeout"
    # nothing failed
    OK = "ok"
    UNKNOWN = "unknown"


class Patch(BaseModel):
    """A machine-applicable change to the request. Not every fix has one:
    "refresh your token" cannot be applied automatically."""

    set_headers: list[tuple[str, str]] = Field(default_factory=list)
    remove_headers: list[str] = Field(default_factory=list)
    method: str | None = None
    url: str | None = None
    body: str | None = None

    def apply(self, req: Request) -> Request:
        drop = {h.lower() for h in self.remove_headers} | {k.lower() for k, _ in self.set_headers}
        headers = [(k, v) for k, v in req.headers if k.lower() not in drop]
        headers += self.set_headers
        return Request(
            method=self.method or req.method,
            url=self.url or req.url,
            headers=headers,
            body=self.body if self.body is not None else req.body,
        )


class Finding(BaseModel):
    """One rule's conclusion. Evidence items quote the trace, so they can be checked."""

    rule: str = ""
    category: Category
    summary: str
    evidence: list[str]
    fix: str
    confidence: float = Field(ge=0, le=1)
    patch: Patch | None = None


class Diagnosis(BaseModel):
    category: Category
    summary: str  # one plain-English sentence: the cause
    evidence: list[str]  # facts from the trace that support it
    fix: str  # what to do
    confidence: float = Field(ge=0, le=1)
    source: Literal["rules", "llm", "rules+llm"] = "rules"
    fixed_request: Request | None = None
    # Every rule that fired, best first: shown at -v, and given to the LLM.
    findings: list[Finding] = Field(default_factory=list)

    def redacted(self, r: Redactor) -> Diagnosis:
        def red_patch(p: Patch | None) -> Patch | None:
            if p is None:
                return None
            return p.model_copy(
                update={
                    "set_headers": r.headers(p.set_headers),
                    "url": r.text(p.url) if p.url else None,
                    "body": r.text(p.body) if p.body else p.body,
                }
            )

        def red_finding(f: Finding) -> Finding:
            return f.model_copy(
                update={
                    "summary": r.text(f.summary),
                    "evidence": [r.text(e) for e in f.evidence],
                    "fix": r.text(f.fix),
                    "patch": red_patch(f.patch),
                }
            )

        return self.model_copy(
            update={
                "summary": r.text(self.summary),
                "evidence": [r.text(e) for e in self.evidence],
                "fix": r.text(self.fix),
                "fixed_request": self.fixed_request.redacted(r) if self.fixed_request else None,
                "findings": [red_finding(f) for f in self.findings],
            }
        )
