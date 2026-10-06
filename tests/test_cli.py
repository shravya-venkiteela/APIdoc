"""The `apidoc` command end to end: output levels, logging, and no leaks.

The leak tests use the noisiest settings (-vvv, --log-json) on purpose: if a
secret survives anywhere, it survives there.
"""

import json

import pytest
from typer.testing import CliRunner

from apidoc.cli import app
from apidoc.diagnosis import Diagnosis

runner = CliRunner()

TOKEN = "s3cret-cli-t0ken-value"
API_KEY = "query-key-0123456789"
COOKIE = "client-cookie-abcdef123"
SERVER_COOKIE = "srv-issued-cookie-9f8e7d6c5b4a"


def apidoc(*args: str, input: str | None = None):
    return runner.invoke(app, list(args), input=input)


def test_default_output_is_short(live_server):
    r = apidoc("diagnose", f"curl {live_server}/v1/limited", "--llm", "never")
    assert r.exit_code == 0, r.output
    assert "Cause: You hit the API's rate limit." in r.stdout
    assert "Fix:" in r.stdout
    assert "Evidence:" not in r.stdout  # beginners get cause + fix only


def test_v_adds_evidence_and_llm_note(live_server):
    r = apidoc("diagnose", f"curl {live_server}/v1/limited", "--llm", "never", "-v")
    assert "Evidence:" in r.stdout and "retry-after: 30" in r.stdout
    assert "LLM disabled" in r.stdout
    assert "Trace (" not in r.stdout


def test_vv_adds_hops_with_timing(live_server):
    r = apidoc("diagnose", f"curl -L {live_server}/v1/old-me", "--llm", "never", "-vv")
    assert "Trace (2 hop(s)" in r.stdout
    assert "-> 302 Found" in r.stdout and "-> 401 Unauthorized" in r.stdout
    assert " ms)" in r.stdout


def test_vvv_adds_headers_and_bodies(live_server):
    r = apidoc("diagnose", f"curl {live_server}/v1/limited", "--llm", "never", "-vvv")
    assert "Hop 1 response:" in r.stdout
    assert "rate limit exceeded" in r.stdout


def test_fixed_request_is_shown(live_server):
    r = apidoc(
        "diagnose", f"curl -H 'Authorization: good-token' {live_server}/v1/me", "--llm", "never"
    )
    assert "Fixed request:" in r.stdout
    assert "Authorization: Bearer [REDACTED]" in r.stdout


@pytest.mark.parametrize("extra", [["-vvv"], ["-vvv", "--log-json"], ["--json"]])
def test_no_secret_anywhere_at_full_verbosity(live_server, extra):
    command = (
        f"curl -L -H 'Authorization: Bearer {TOKEN}' -b 'sid={COOKIE}' "
        f"'{live_server}/v1/old-me?api_key={API_KEY}'"
    )
    r = apidoc("diagnose", command, "--llm", "never", *extra)
    assert r.exit_code == 0, r.output
    everything = r.stdout + r.stderr
    for secret in (TOKEN, API_KEY, COOKIE):
        assert secret not in everything, secret


def test_cookie_set_by_the_server_is_masked(live_server):
    """A secret APIdoc never saw in the command: masked by header name."""
    r = apidoc("diagnose", f"curl {live_server}/v1/session", "--llm", "never", "-vvv")
    assert SERVER_COOKIE not in r.stdout + r.stderr
    assert "sid=[REDACTED]" in r.stdout


def test_gemini_key_is_never_printed(live_server, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-fake-key-for-logging-test-000000")
    r = apidoc("diagnose", f"curl {live_server}/v1/limited", "-vvv", "--log-json")
    assert "AIza-fake-key" not in r.stdout + r.stderr


def test_log_json_lines_are_valid_and_structured(live_server):
    r = apidoc("diagnose", f"curl -L {live_server}/v1/old-me", "--llm", "never", "-vv",
               "--log-json")  # fmt: skip
    lines = [json.loads(line) for line in r.stderr.splitlines() if line.strip()]
    assert lines and all({"ts", "level", "logger", "msg"} <= set(e) for e in lines)
    hops = [e for e in lines if e.get("event") == "hop"]
    assert [h["status"] for h in hops] == [302, 401]
    assert all("elapsed_ms" in h for h in hops)


def test_default_verbosity_logs_nothing(live_server):
    r = apidoc("diagnose", f"curl {live_server}/v1/limited", "--llm", "never")
    assert r.stderr == ""


def test_json_output_is_a_valid_diagnosis(live_server):
    r = apidoc("diagnose", f"curl {live_server}/v1/limited", "--llm", "never", "--json")
    d = Diagnosis.model_validate_json(r.stdout)
    assert d.category == "rate_limited"


def test_unsafe_method_is_refused(live_server):
    r = apidoc("diagnose", f"curl -X DELETE {live_server}/v1/me", "--llm", "never")
    assert r.exit_code == 2
    assert "--allow-unsafe" in r.stderr


def test_save_then_analyse_trace_without_rerunning(live_server, tmp_path):
    saved = tmp_path / "trace.json"
    command = f"curl -L -H 'Authorization: Bearer {TOKEN}' {live_server}/v1/old-me"
    first = apidoc("diagnose", command, "--llm", "never", "--save-trace", str(saved))
    assert first.exit_code == 0
    assert TOKEN not in saved.read_text(encoding="utf-8")

    second = apidoc("diagnose", "--trace-file", str(saved), "--llm", "never", "--json")
    assert Diagnosis.model_validate_json(second.stdout).category == "auth_dropped_on_redirect"


def test_export_writes_a_working_fix_with_real_credentials(live_server, tmp_path):
    out = tmp_path / "fixed.txt"
    command = f"curl -L -H 'Authorization: Bearer good-token' {live_server}/v1/old-me"
    r = apidoc("diagnose", command, "--llm", "never", "--export", str(out))
    text = out.read_text(encoding="utf-8")
    assert "Bearer good-token" in text  # the file must work...
    assert "localhost" in text  # ...and call the final URL directly
    assert "real credentials" in r.stderr  # ...and the user is warned
    assert "good-token" not in r.stdout  # the screen copy stays redacted


def test_command_from_stdin_and_file(live_server, tmp_path):
    cmd = f"curl {live_server}/v1/limited"
    assert "rate limit" in apidoc("diagnose", "-", "--llm", "never", input=cmd).stdout
    f = tmp_path / "cmd.txt"
    f.write_text(cmd, encoding="utf-8")
    assert "rate limit" in apidoc("diagnose", "-f", str(f), "--llm", "never").stdout


def test_bad_curl_is_a_clear_error():
    r = apidoc("diagnose", "curl -H")
    assert r.exit_code == 2
    assert "could not parse" in r.stderr


def test_convert_to_httpx():
    r = apidoc("convert", "curl -X POST --json '{\"a\": 1}' https://api.test/x", "--to", "httpx")
    assert "httpx.request(" in r.stdout and "'POST'" in r.stdout


def test_llm_always_without_key_says_so(live_server):
    r = apidoc("diagnose", f"curl {live_server}/v1/limited", "--llm", "always")
    assert r.exit_code == 0, r.output
    assert "LLM was not used" in r.stderr
    assert "no Gemini key" in r.stderr


def test_llm_auto_falls_back_quietly(live_server):
    r = apidoc("diagnose", f"curl {live_server}/v1/limited", "--llm", "auto")
    assert r.exit_code == 0, r.output
    assert "LLM was not used" not in r.stderr
