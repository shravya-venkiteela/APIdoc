from __future__ import annotations

import os
import re
import sys
import time
import webbrowser
from pathlib import Path
from typing import Annotated

import typer

from apidoc import __version__, logs, oauth, profiles
from apidoc.curl import CurlParseError, ParsedCurl, parse_curl
from apidoc.diagnose import LLMOutcome, diagnose
from apidoc.diagnosis import Category, Diagnosis
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
DEFAULT_BASE_URL = "http://127.0.0.1:8000"


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


def _scope_fix(d: Diagnosis, trace: Trace, profile: str | None) -> Diagnosis:
    """With --profile, a missing-scope fix can name the exact command to run."""
    if profile is None or d.category != Category.AUTH_SCOPE or trace.final is None:
        return d
    needed = re.search(r'scope="([^"]+)"', trace.final.header("www-authenticate") or "")
    if not needed:
        return d
    s = profiles.load(profile)
    scope = " ".join(dict.fromkeys([*s.get("scope", "").split(), *needed.group(1).split()]))
    cmd = f'apidoc auth login --profile {profile} --scope "{scope}"'
    if s.get("provider", "mock") != "mock":
        cmd += f" --provider {s['provider']}"
    if s.get("base_url") and s.get("base_url") != DEFAULT_BASE_URL:
        cmd += f" --base-url {s['base_url']}"
    return d.model_copy(update={"fix": f"{d.fix} Run: {cmd}"})


def _gemini_key() -> tuple[str | None, str]:
    """(key, where it came from). The environment variable wins over the keyring."""
    if key := os.environ.get("GEMINI_API_KEY"):
        return key, "the GEMINI_API_KEY environment variable"
    return profiles.get_secret("gemini", "api_key"), "the keyring (`apidoc key set gemini`)"


def _provider(mode: str):
    if mode == "never":
        return None, "LLM disabled (--llm never)"
    try:
        key, source = _gemini_key()
        return GeminiProvider(key or "", key_source=source), ""
    except LLMError:
        return None, "no Gemini key (GEMINI_API_KEY or `apidoc key set gemini`): rules only"


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
    profile: Annotated[
        str | None, typer.Option(help="Profile whose stored secrets are also redacted.")
    ] = None,
    with_token: Annotated[
        bool, typer.Option(help="Add the profile's access token if the request has none.")
    ] = False,
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

    redactor.add(_gemini_key()[0])  # never log our own key either
    if profile is not None:
        try:
            profiles.load(profile)
        except profiles.ProfileError as exc:
            raise _fail(str(exc)) from exc
        for secret in profiles.secrets_of(profile):
            redactor.add(secret)
        if with_token and not parsed.request.has_header("authorization"):
            token = profiles.get_secret(profile, "access_token")
            if token is None:
                raise _fail(f"profile {profile!r} has no stored token: run `apidoc auth login`")
            headers = [*parsed.request.headers, ("Authorization", f"Bearer {token}")]
            parsed = parsed.model_copy(
                update={"request": parsed.request.model_copy(update={"headers": headers})}
            )
    elif with_token:
        raise _fail("--with-token needs --profile")
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
    d = _scope_fix(d, trace, profile)
    log.info("diagnosis: %s (%.2f, %s)", d.category.value, d.confidence, d.source)
    if llm == "always" and not outcome.used:
        # The user asked for the LLM explicitly; falling back silently would hide it.
        typer.secho(
            f"Note: --llm always, but the LLM was not used: {note or outcome.reason}",
            fg="yellow",
            err=True,
        )

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


auth_app = typer.Typer(no_args_is_help=True, help="OAuth login; tokens go to the OS keyring.")
app.add_typer(auth_app, name="auth")
# Indirection so tests can drive the "browser" without opening one.
open_browser = webbrowser.open


def _announce_and_open(url: str) -> object:
    # Printed only once the server is known to be reachable.
    typer.echo("Opening your browser to sign in...")
    return open_browser(url)


def _config(profile: str) -> oauth.ProviderConfig:
    s = profiles.load(profile)
    return oauth.preset(s["provider"], s.get("base_url", ""), s["client_id"], s.get("scope", ""))


def _store_tokens(profile: str, tok: oauth.TokenSet) -> None:
    profiles.set_secret(profile, "access_token", tok.access_token)
    if tok.refresh_token:
        profiles.set_secret(profile, "refresh_token", tok.refresh_token)
    profiles.save(profile, {"scope": tok.scope, "expires_at": str(tok.expires_at or "")})


def _expiry(settings: dict[str, str]) -> str:
    raw = settings.get("expires_at")
    if not raw:
        return "unknown expiry"
    left = float(raw) - time.time()
    return f"expired {-left / 60:.0f} min ago" if left < 0 else f"expires in {left / 60:.0f} min"


@auth_app.command("login")
def auth_login(
    profile: Annotated[str, typer.Option(help="Name to store this login under.")] = "mock",
    provider: Annotated[str, typer.Option(help="mock | github | google")] = "mock",
    base_url: Annotated[str, typer.Option(help="Mock server URL.")] = DEFAULT_BASE_URL,
    flow: Annotated[str, typer.Option(help="pkce | client-credentials")] = "pkce",
    client_id: Annotated[str | None, typer.Option(help="OAuth client id.")] = None,
    scope: Annotated[str, typer.Option(help="Space-separated scopes.")] = "read",
    mock_ttl: Annotated[
        int | None, typer.Option(hidden=True, help="Mock server only: token lifetime (s).")
    ] = None,
) -> None:
    """Log in with OAuth 2.0 and store the tokens in the OS keyring."""
    if flow not in ("pkce", "client-credentials"):
        raise _fail("--flow must be pkce or client-credentials")
    client_id = client_id or ("demo-cli" if flow == "pkce" else "demo-service")
    try:
        cfg = oauth.preset(provider, base_url, client_id, scope)
    except oauth.OAuthError as exc:
        raise _fail(str(exc)) from exc
    extra = {"ttl": str(mock_ttl)} if mock_ttl is not None and provider == "mock" else None
    try:
        if flow == "pkce":
            tok = oauth.login_pkce(cfg, open_browser=_announce_and_open, extra_token_params=extra)
        else:
            secret = profiles.get_secret(profile, "client_secret") or typer.prompt(
                "Client secret", hide_input=True
            )
            tok = oauth.client_credentials(cfg, secret, extra_token_params=extra)
            profiles.set_secret(profile, "client_secret", secret)
        profiles.save(
            profile,
            {"provider": provider, "base_url": base_url, "client_id": client_id, "flow": flow},
        )
        _store_tokens(profile, tok)
    except (oauth.OAuthError, profiles.ProfileError) as exc:
        raise _fail(str(exc)) from exc
    typer.secho(
        f"Logged in as profile {profile!r} (scope: {tok.scope or '-'}). Token stored in "
        f"{profiles.backend_name()}; it is not shown.",
        fg="green",
    )


@auth_app.command("status")
def auth_status(profile: Annotated[str, typer.Option()] = "mock") -> None:
    """Show what is stored for a profile, without revealing any secret."""
    try:
        s = profiles.load(profile)
    except profiles.ProfileError as exc:
        raise _fail(str(exc)) from exc
    has = {f: profiles.get_secret(profile, f) is not None for f in profiles.SECRET_FIELDS}
    typer.echo(f"profile:  {profile} ({s.get('provider')}, {s.get('flow')})")
    typer.echo(f"client:   {s.get('client_id')}")
    typer.echo(f"scope:    {s.get('scope') or '-'}")
    typer.echo(f"token:    {'stored, ' + _expiry(s) if has['access_token'] else 'none'}")
    typer.echo(f"refresh:  {'stored' if has['refresh_token'] else 'none'}")
    typer.echo(f"keyring:  {profiles.backend_name()}")


@auth_app.command("refresh")
def auth_refresh(profile: Annotated[str, typer.Option()] = "mock") -> None:
    """Get a new access token (refresh token, or client credentials again)."""
    try:
        cfg = _config(profile)
        s = profiles.load(profile)
        rt = profiles.get_secret(profile, "refresh_token")
        if rt:
            tok = oauth.refresh(cfg, rt)
        elif s.get("flow") == "client-credentials":
            secret = profiles.get_secret(profile, "client_secret")
            if not secret:
                raise _fail("no stored client secret: run `apidoc auth login` again")
            tok = oauth.client_credentials(cfg, secret)
        else:
            raise _fail("no refresh token stored: run `apidoc auth login` again")
        _store_tokens(profile, tok)
    except (oauth.OAuthError, profiles.ProfileError) as exc:
        raise _fail(str(exc)) from exc
    typer.secho(f"Refreshed {profile!r} ({_expiry(profiles.load(profile))}).", fg="green")


@auth_app.command("logout")
def auth_logout(profile: Annotated[str, typer.Option()] = "mock") -> None:
    """Delete a profile and every secret stored for it."""
    profiles.delete(profile)
    typer.echo(f"Removed profile {profile!r} and its stored secrets.")


# ------------------------------------------------------------ keys ----------

key_app = typer.Typer(no_args_is_help=True, help="API keys in the OS keyring.")
app.add_typer(key_app, name="key")


@key_app.command("set")
def key_set(
    name: Annotated[str, typer.Argument(help="'gemini' for the LLM key, or a profile name.")],
) -> None:
    """Store an API key (read from a hidden prompt, never from the command line)."""
    value = typer.prompt(f"API key for {name}", hide_input=True).strip()
    # A hidden prompt shows nothing, so a bad paste (e.g. Ctrl+V arriving as a
    # control character) would otherwise be stored silently.
    if not value.isprintable() or any(c.isspace() for c in value):
        raise _fail("the key contains control characters or spaces: paste it again")
    try:
        profiles.set_secret(name, "api_key", value)
    except profiles.ProfileError as exc:
        raise _fail(str(exc)) from exc
    typer.secho(f"Stored the {name} key in {profiles.backend_name()}.", fg="green")


@key_app.command("rm")
def key_rm(name: Annotated[str, typer.Argument()]) -> None:
    """Delete a stored API key."""
    profiles.delete_secret(name, "api_key")
    typer.echo(f"Removed the {name} key.")


@app.command("profiles")
def list_profiles() -> None:
    """List profiles (settings only; secrets stay in the keyring)."""
    for name in profiles.names():
        s = profiles.load(name)
        typer.echo(f"{name:12} {s.get('provider', '-'):8} {s.get('base_url', '')}  {_expiry(s)}")


if __name__ == "__main__":
    app()
