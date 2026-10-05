import socket
import threading
import time

import pytest
import uvicorn

from mock_server.app import app


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def live_server():
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("mock server did not start")
        time.sleep(0.05)
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
