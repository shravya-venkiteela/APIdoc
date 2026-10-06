"""Profiles and the keyring, plus the auth/key commands that use them."""

import re

import httpx
import pytest
from typer.testing import CliRunner

from apidoc import cli, profiles
from apidoc.diagnosis import Diagnosis

runner = CliRunner()


def apidoc(*args, input=None):
    return runner.invoke(cli.app, list(args), input=input)


@pytest.fixture
def fake_browser(monkeypatch):
    monkeypatch.setattr(
        cli, "open_browser", lambda url: httpx.get(url, follow_redirects=True, timeout=10)
    )


def test_secrets_never_reach_the_profile_file(memory_keyring):
    profiles.save("p", {"provider": "mock", "client_id": "demo-cli"})
    profiles.set_secret("p", "access_token", "tok-should-be-in-keyring-only")
    text = (profiles.config_dir() / "profiles.json").read_text(encoding="utf-8")
    assert "tok-should-be-in-keyring-only" not in text
    assert ("apidoc", "p:access_token") in memory_keyring.store


def test_saving_a_secret_field_to_the_file_is_refused():
    with pytest.raises(profiles.ProfileError, match="refusing"):
        profiles.save("p", {"access_token": "x"})


def test_delete_removes_settings_and_secrets(memory_keyring):
    profiles.save("p", {"provider": "mock"})
    profiles.set_secret("p", "refresh_token", "r")
    profiles.delete("p")
    assert "p" not in profiles.names()
    assert memory_keyring.store == {}


def test_missing_keyring_is_a_clear_error(monkeypatch):
    import keyring.errors

    def broken(*args):
        raise keyring.errors.NoKeyringError("no backend")

    monkeypatch.setattr(profiles.keyring, "set_password", broken)
    with pytest.raises(profiles.ProfileError, match="will not store secrets in a plain file"):
        profiles.set_secret("p", "api_key", "k")


def test_login_pkce_status_and_no_token_on_screen(live_server, fake_browser):
    r = apidoc("auth", "login", "--base-url", live_server, "--scope", "read admin")
    assert r.exit_code == 0, r.output
    token = profiles.get_secret("mock", "access_token")
    assert token and token not in r.output
    status = apidoc("auth", "status")
    assert "stored, expires in" in status.output and token not in status.output


def test_login_client_credentials_prompts_for_secret(live_server):
    r = apidoc(
        "auth", "login", "--profile", "svc", "--flow", "client-credentials",
        "--base-url", live_server, "--scope", "admin", input="demo-service-secret\n",
    )  # fmt: skip
    assert r.exit_code == 0, r.output
    assert profiles.get_secret("svc", "client_secret") == "demo-service-secret"
    assert "demo-service-secret" not in r.output


def test_refresh_command(live_server, fake_browser):
    apidoc("auth", "login", "--base-url", live_server)
    old = profiles.get_secret("mock", "access_token")
    r = apidoc("auth", "refresh")
    assert r.exit_code == 0, r.output
    assert profiles.get_secret("mock", "access_token") != old


def test_diagnose_with_profile_token_end_to_end(live_server, fake_browser):
    """Real OAuth token, wrong scope for the endpoint: diagnosed, nothing leaked."""
    apidoc("auth", "login", "--base-url", live_server, "--scope", "read")
    token = profiles.get_secret("mock", "access_token")
    r = apidoc(
        "diagnose", f"curl {live_server}/v1/admin/users",
        "--profile", "mock", "--with-token", "--llm", "never", "-vvv", "--json",
    )  # fmt: skip
    d = Diagnosis.model_validate_json(r.stdout)
    assert d.category == "auth_scope" and "admin" in d.summary
    assert token not in r.stdout + r.stderr


def test_expired_token_from_the_real_flow_is_diagnosed(live_server, fake_browser):
    apidoc("auth", "login", "--base-url", live_server, "--mock-ttl", "-120")
    r = apidoc(
        "diagnose", f"curl {live_server}/v1/me", "--profile", "mock", "--with-token",
        "--llm", "never", "--json",
    )  # fmt: skip
    assert Diagnosis.model_validate_json(r.stdout).category == "auth_expired"
    assert "expired" in apidoc("auth", "status").output


def test_logout(live_server, fake_browser, memory_keyring):
    apidoc("auth", "login", "--base-url", live_server)
    apidoc("auth", "logout")
    assert memory_keyring.store == {}
    assert apidoc("auth", "status").exit_code == 2


def test_gemini_key_from_keyring_is_used_and_redacted(live_server):
    apidoc("key", "set", "gemini", input="AIza-keyring-stored-key-0000000000\n")
    assert profiles.get_secret("gemini", "api_key") == "AIza-keyring-stored-key-0000000000"
    assert cli._gemini_key() == "AIza-keyring-stored-key-0000000000"
    r = apidoc("diagnose", f"curl {live_server}/v1/limited", "--llm", "never", "-vvv")
    assert "AIza-keyring" not in r.stdout + r.stderr
    apidoc("key", "rm", "gemini")
    assert profiles.get_secret("gemini", "api_key") is None


def test_profiles_command_lists_without_secrets(live_server, fake_browser):
    apidoc("auth", "login", "--base-url", live_server)
    out = apidoc("profiles").output
    assert re.search(r"^mock\s+mock", out, re.M)
    assert profiles.get_secret("mock", "access_token") not in out
