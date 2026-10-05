from __future__ import annotations

import shlex
from typing import Literal

from apidoc.models import Request

Shell = Literal["posix", "powershell"]


def _ps_quote(value: str) -> str:
    # PowerShell single-quoted string: the only escape is '' for '.
    return "'" + value.replace("'", "''") + "'"


def to_curl(
    req: Request,
    *,
    follow_redirects: bool = False,
    verify_tls: bool = True,
    shell: Shell = "posix",
) -> str:
    quote = shlex.quote if shell == "posix" else _ps_quote
    parts = ["curl.exe" if shell == "powershell" else "curl"]

    implied = "POST" if req.body is not None else "GET"
    if req.method != implied:
        parts += ["-X", req.method]
    for name, value in req.headers:
        parts += ["-H", quote(f"{name}: {value}")]
    if req.body is not None:
        parts += ["--data-raw", quote(req.body)]
    if follow_redirects:
        parts.append("-L")
    if not verify_tls:
        parts.append("-k")
    parts.append(quote(req.url))

    joiner = " \\\n  " if shell == "posix" else " `\n  "
    return joiner.join(parts) if len(parts) > 4 else " ".join(parts)


def to_httpx(req: Request, *, follow_redirects: bool = False, verify_tls: bool = True) -> str:
    lines = ["import httpx", "", "response = httpx.request("]
    lines.append(f"    {req.method!r},")
    lines.append(f"    {req.url!r},")
    if req.headers:
        lines.append("    headers=[")
        lines += [f"        ({k!r}, {v!r})," for k, v in req.headers]
        lines.append("    ],")
    if req.body is not None:
        lines.append(f"    content={req.body!r},")
    if follow_redirects:
        lines.append("    follow_redirects=True,")
    if not verify_tls:
        lines.append("    verify=False,")
    lines += [")", "print(response.status_code, response.text)", ""]
    return "\n".join(lines)
