from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated

import typer

from apidoc import __version__, logs
from apidoc.curl import CurlParseError, ParsedCurl, parse_curl
from apidoc.diagnose import LLMOutcome, diagnose
from apidoc.diagnosis import Diagnosis
from apidoc.export import to_curl, to_httpx
from apidoc.llm import GeminiProvider, LLMError
from apidoc.redact import Redactor
from apidoc.rules import Context
from apidoc.runner import UnsafeRequestError, run
from apidoc.trace import Trace

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Diagnose failing API calls: re-run with a trace, explain why, export a fix.",
)

EXIT_OK = 0
EXIT_USAGE = 2


def _fail(message: str) -> typer.Exit:
    typer.secho(f"error: {message}", fg="red", err=True)
    return typer.Exit(EXIT_USAGE)


def _read_command(command: str | None, from_file: Path | None) -> str:
    if from_file is not None:
        return from_file.read_text(encoding="utf-8")
    if command is None or command == "-":
        if sys.stdin.isatty():
            raise _fail("give a curl command, -f FILE, or pipe one in")
        return sys.stdin.read()
    return command


def _provider(mode: str):
    if mode == "never":
        return None, "LLM disabled (--llm never)"
    try:
        return GeminiProvider.from_env(), ""
    except LLMError:
        return None, "no GEMINI_API_KEY set: rules only"


def _section(title: str) -> None:
    typer.secho(f"\n{title}", bold=True)


def _render(
    d: Diagnosis,
    outcome: LLMOutcome,
    trace: Trace,
    parsed: ParsedCurl,
    verbosity: int,
    note: str,
) -> None:
    color = "green" if d.category.value == "ok" else "yellow"
    typer.secho(f"Cause: {d.summary}", fg=color, bold=True)
    typer.echo(f"Fix:   {d.fix}")
    typer.secho(f"({d.category.value}, confidence {d.confidence:.2f}, from {d.source})", dim=True)

    if d.fixed_request is not None:
        _section("Fixed request:")
        typer.echo(to_curl(d.fixed_request, follow_redirects=parsed.follow_redirects))

    if verbosity >= 1:
        _section("Evidence:")
        for item in d.evidence:
            typer.echo(f"  - {item}")
        others = [f for f in d.findings if f.category != d.category]
        if others:
            _section("Other possible causes:")
            for f in others:
                typer.echo(f"  - [{f.confidence:.2f}] {f.summary}")
        _section("LLM:")
        typer.echo(f"  {outcome.reason or note}")
        if outcome.dropped_evidence:
            typer.echo(f"  dropped {len(outcome.dropped_evidence)} ungrounded evidence item(s)")
        if parsed.implicit_headers:
            added = ", ".join(f"{k}: {v}" for k, v in parsed.implicit_headers)
            typer.echo(f"  note: curl added these headers itself: {added}")
        for warning in parsed.warnings:
            typer.echo(f"  warning: {warning}")

    if verbosity >= 2:
        _section(f"Trace ({len(trace.hops)} hop(s), {trace.total_ms:.0f} ms total):")
        if trace.error:
            typer.echo(f"  no response: {trace.error_kind}: {trace.error}")
        for i, hop in enumerate(trace.hops, start=1):
            typer.echo(
                f"  {i}. {hop.request.method} {hop.request.url} -> "
                f"{hop.status} {hop.reason} ({hop.elapsed_ms:.0f} ms)"
            )

    if verbosity >= 3:
        for i, hop in enumerate(trace.hops, start=1):
            _section(f"Hop {i} request:")
            typer.echo(f"  {hop.request.method} {hop.request.url}")
            for k, v in hop.request.headers:
                typer.echo(f"  {k}: {v}")
            if hop.request.body:
                typer.echo(f"\n  {hop.request.body[:2000]}")
            _section(f"Hop {i} response:")
            typer.echo(f"  {hop.http_version} {hop.status} {hop.reason}")
            for k, v in hop.headers:
                typer.echo(f"  {k}: {v}")
            if hop.body:
                more = " ...(truncated)" if hop.body_truncated or len(hop.body) > 2000 else ""
                typer.echo(f"\n  {hop.body[:2000]}{more}")


@app.command(name="diagnose")
def diagnose_cmd(
    command: Annotated[
        str | None, typer.Argument(help="The failing curl command, in quotes. '-' reads stdin.")
    ] = None,
    from_file: Annotated[
        Path | None, typer.Option("--file", "-f", help="Read the curl command from a file.")
    ] = None,
    trace_file: Annotated[
        Path | None,
        typer.Option(help="Analyse a saved trace instead of re-running the request."),
    ] = None,
    save_trace: Annotated[
        Path | None, typer.Option(help="Save the (redacted) trace as JSON.")
    ] = None,
    allow_unsafe: Annotated[
        bool, typer.Option(help="Allow re-running POST/PUT/PATCH/DELETE.")
    ] = False,
    llm: Annotated[
        str, typer.Option(help="auto: only when rules are unsure. always | never.")
    ] = "auto",
    as_json: Annotated[bool, typer.Option("--json", help="Print the Diagnosis as JSON.")] = False,
    export: Annotated[
        Path | None,
        typer.Option(help="Write the fixed request to this file (with real credentials)."),
    ] = None,
    export_format: Annotated[str, typer.Option(help="curl | powershell | httpx")] = "curl",
    verbose: Annotated[
        int, typer.Option("--verbose", "-v", count=True, help="-v, -vv or -vvv.")
    ] = 0,
    log_json: Annotated[bool, typer.Option(help="Logs as JSON lines on stderr.")] = False,
) -> None:
    """Re-run a failing request with a trace and explain why it failed."""
    if llm not in ("auto", "always", "never"):
        raise _fail("--llm must be auto, always or never")
    if export_format not in ("curl", "powershell", "httpx"):
        raise _fail("--export-format must be curl, powershell or httpx")

    if trace_file is not None:
        trace = Trace.from_json(trace_file.read_text(encoding="utf-8"))
        if not trace.hops:
            raise _fail("the saved trace has no hops to analyse")
        parsed = ParsedCurl(request=trace.hops[0].request, follow_redirects=trace.follow_redirects)
        redactor = Redactor()
    else:
        try:
            parsed = parse_curl(_read_command(command, from_file))
        except CurlParseError as exc:
            raise _fail(f"could not parse the curl command: {exc}") from exc
        redactor = parsed.redactor()

    api_key = os.environ.get("GEMINI_API_KEY")
    redactor.add(api_key)  # never log our own key either
    log = logs.configure(verbose, log_json, redactor)
    log.info("apidoc %s", __version__)

    if trace_file is None:
        try:
            trace = run(parsed, allow_unsafe=allow_unsafe)
        except UnsafeRequestError as exc:
            raise _fail(str(exc)) from exc
    if save_trace is not None:
        save_trace.write_text(trace.redacted(redactor).to_json(), encoding="utf-8")
        log.info("saved redacted trace to %s", save_trace)

    provider, note = _provider(llm)
    d, outcome = diagnose(Context(parsed, trace), redactor, provider, mode=llm)
    log.info("diagnosis: %s (%.2f, %s)", d.category.value, d.confidence, d.source)

    if export is not None and d.fixed_request is not None:
        # The display copy is redacted; the exported file must work, so it keeps
        # the real credentials. Rebuild the fix from the unredacted rule finding.
        from apidoc.rules import diagnose_with_rules

        raw = diagnose_with_rules(Context(parsed, trace)).fixed_request or d.fixed_request
        if export_format == "httpx":
            text = to_httpx(raw, follow_redirects=parsed.follow_redirects)
        else:
            shell = "powershell" if export_format == "powershell" else "posix"
            text = to_curl(raw, follow_redirects=parsed.follow_redirects, shell=shell) + "\n"
        export.write_text(text, encoding="utf-8")
        typer.secho(
            f"Wrote the fixed request to {export}. It contains your real credentials: "
            "do not commit or share it.",
            fg="yellow",
            err=True,
        )
    elif export is not None:
        typer.secho("No machine-applicable fix for this cause; nothing exported.", err=True)

    if as_json:
        typer.echo(d.model_dump_json(indent=2))
    else:
        _render(d, outcome, trace.redacted(redactor), parsed, verbose, note)


@app.command()
def convert(
    command: Annotated[str | None, typer.Argument(help="curl command, or '-' for stdin")] = None,
    from_file: Annotated[Path | None, typer.Option("--file", "-f")] = None,
    to: Annotated[str, typer.Option(help="curl | powershell | httpx")] = "httpx",
) -> None:
    """Convert a curl command to httpx code, or normalise it for bash or PowerShell."""
    try:
        parsed = parse_curl(_read_command(command, from_file))
    except CurlParseError as exc:
        raise _fail(f"could not parse the curl command: {exc}") from exc
    req, follow = parsed.request, parsed.follow_redirects
    if to == "httpx":
        typer.echo(to_httpx(req, follow_redirects=follow, verify_tls=parsed.verify_tls))
    elif to in ("curl", "powershell"):
        shell = "powershell" if to == "powershell" else "posix"
        typer.echo(to_curl(req, follow_redirects=follow, verify_tls=parsed.verify_tls, shell=shell))
    else:
        raise _fail("--to must be curl, powershell or httpx")


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(f"apidoc {__version__}")


if __name__ == "__main__":
    app()
