from __future__ import annotations

import json
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from apidoc.models import Request
from apidoc.redact import Redactor


class Hop(BaseModel):
    """One request/response exchange."""

    request: Request  # exactly what was sent, including headers the client added
    status: int
    reason: str = ""
    http_version: str = "HTTP/1.1"
    headers: list[tuple[str, str]] = Field(default_factory=list)
    body: str = ""
    body_truncated: bool = False
    elapsed_ms: float = 0.0

    def header(self, name: str) -> str | None:
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), None)

    def json_body(self) -> object | None:
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None

    def redacted(self, r: Redactor) -> Hop:
        parsed = self.json_body()
        body = json.dumps(r.json(parsed)) if parsed is not None else r.text(self.body)
        return self.model_copy(
            update={
                "request": self.request.redacted(r),
                "headers": r.headers(self.headers),
                "body": body,
            }
        )


class Trace(BaseModel):
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    hops: list[Hop] = Field(default_factory=list)
    follow_redirects: bool = False
    total_ms: float = 0.0
    # Set when no final response was received (connection refused, TLS, timeout...).
    error: str | None = None
    error_kind: str | None = None
    # True once redact() has run: a saved trace on disk is always redacted.
    is_redacted: bool = False

    @property
    def final(self) -> Hop | None:
        return self.hops[-1] if self.hops else None

    @property
    def first(self) -> Hop | None:
        return self.hops[0] if self.hops else None

    def redacted(self, r: Redactor) -> Trace:
        return self.model_copy(
            update={
                "hops": [h.redacted(r) for h in self.hops],
                "error": r.text(self.error) if self.error else None,
                "is_redacted": True,
            }
        )

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    @classmethod
    def from_json(cls, text: str) -> Trace:
        return cls.model_validate_json(text)
