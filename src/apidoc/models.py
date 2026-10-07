"""Core data types shared by every stage of the pipeline."""

from __future__ import annotations

from pydantic import BaseModel, Field

from apidoc.redact import Redactor


class Request(BaseModel):
    """An HTTP request, independent of where it came from (curl, Postman, ...).

    Headers are a list of pairs, not a dict: order is kept, and duplicate
    headers (two Cookie lines, say) are legal in HTTP and must survive.
    """

    method: str = "GET"
    url: str
    headers: list[tuple[str, str]] = Field(default_factory=list)
    body: str | None = None

    def header(self, name: str) -> str | None:
        """First value of a header, case-insensitive."""
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), None)

    def has_header(self, name: str) -> bool:
        return self.header(name) is not None

    def redacted(self, redactor: Redactor) -> Request:
        return Request(
            method=self.method,
            url=redactor.text(self.url),
            headers=redactor.headers(self.headers),
            body=redactor.text(self.body) if self.body else self.body,
        )
