"""Profiles: non-secret settings in a JSON file, secrets in the OS keyring.

On Windows the keyring is Windows Credential Manager, on macOS the Keychain,
on Linux the Secret Service (GNOME Keyring / KWallet). Secrets are never
written to the JSON file; a test reads the file back to prove it.

    profiles.json   {"mock": {"provider": "mock", "base_url": ..., "client_id": ...}}
    keyring         service "apidoc", user "mock:access_token" -> the token
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import keyring
import keyring.errors

SERVICE = "apidoc"
SECRET_FIELDS = ("access_token", "refresh_token", "client_secret", "api_key")


class ProfileError(RuntimeError):
    pass


def config_dir() -> Path:
    if override := os.environ.get("APIDOC_CONFIG_DIR"):
        return Path(override)
    if appdata := os.environ.get("APPDATA"):  # Windows
        return Path(appdata) / "apidoc"
    return Path.home() / ".config" / "apidoc"


def _path() -> Path:
    return config_dir() / "profiles.json"


def _load_all() -> dict[str, dict]:
    path = _path()
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _save_all(data: dict[str, dict]) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def save(name: str, settings: dict[str, str]) -> None:
    leaked = [k for k in settings if k in SECRET_FIELDS]
    if leaked:
        raise ProfileError(f"refusing to write secrets to the profile file: {leaked}")
    data = _load_all()
    data[name] = {**data.get(name, {}), **settings}
    _save_all(data)


def load(name: str) -> dict[str, str]:
    data = _load_all()
    if name not in data:
        raise ProfileError(f"no profile named {name!r}. Create one with `apidoc auth login`.")
    return data[name]


def names() -> list[str]:
    return sorted(_load_all())


def delete(name: str) -> None:
    data = _load_all()
    data.pop(name, None)
    _save_all(data)
    for field in SECRET_FIELDS:
        delete_secret(name, field)


def _user(profile: str, field: str) -> str:
    return f"{profile}:{field}"


def set_secret(profile: str, field: str, value: str) -> None:
    try:
        keyring.set_password(SERVICE, _user(profile, field), value)
    except keyring.errors.KeyringError as exc:
        raise ProfileError(
            f"no usable OS keyring ({exc}). APIdoc will not store secrets in a plain file; "
            "on headless Linux install a Secret Service, or use environment variables."
        ) from exc


def get_secret(profile: str, field: str) -> str | None:
    try:
        return keyring.get_password(SERVICE, _user(profile, field))
    except keyring.errors.KeyringError:
        return None


def delete_secret(profile: str, field: str) -> None:
    try:
        keyring.delete_password(SERVICE, _user(profile, field))
    except keyring.errors.KeyringError:
        pass  # already gone, or no keyring: nothing to delete


def secrets_of(profile: str) -> list[str]:
    """Every stored secret of a profile, for the Redactor."""
    return [v for f in SECRET_FIELDS if (v := get_secret(profile, f))]


def backend_name() -> str:
    return type(keyring.get_keyring()).__name__
