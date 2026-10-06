import pytest

from mock_server import serve


@pytest.fixture(scope="session")
def live_server():
    server, thread, port = serve.start()
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch):
    """Tests must not depend on the developer's shell. A GEMINI_API_KEY or
    APIDOC_GEMINI_THINKING left set in the terminal would otherwise change
    behaviour (and could make a test call the real API)."""
    for name in ("GEMINI_API_KEY", "APIDOC_GEMINI_MODEL", "APIDOC_GEMINI_THINKING"):
        monkeypatch.delenv(name, raising=False)


class MemoryKeyring:
    """A keyring backend that lives in a dict, so tests never touch the real
    Windows Credential Manager / macOS Keychain."""

    priority = 1

    def __init__(self):
        self.store = {}

    def get_password(self, service, user):
        return self.store.get((service, user))

    def set_password(self, service, user, password):
        self.store[(service, user)] = password

    def delete_password(self, service, user):
        import keyring.errors

        if (service, user) not in self.store:
            raise keyring.errors.PasswordDeleteError("not found")
        del self.store[(service, user)]


@pytest.fixture(autouse=True)
def memory_keyring(monkeypatch, tmp_path):
    import keyring
    from keyring.backend import KeyringBackend

    backend_cls = type("MemoryKeyring", (MemoryKeyring, KeyringBackend), {})
    backend = backend_cls()
    previous = keyring.get_keyring()
    keyring.set_keyring(backend)
    monkeypatch.setenv("APIDOC_CONFIG_DIR", str(tmp_path / "apidoc-config"))
    yield backend
    keyring.set_keyring(previous)
