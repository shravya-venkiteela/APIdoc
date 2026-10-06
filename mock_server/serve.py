from __future__ import annotations

import socket
import sys
import threading
import time

import uvicorn

from mock_server.app import app


def _bind(family: socket.AddressFamily, host: str, port: int) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_STREAM)
    if sys.platform != "win32":
        # Allow quick restarts on the same port. (On Windows this option would
        # let another process take over a port in use, so it stays off there.)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    try:
        sock.bind((host, port))
    except OSError:
        sock.close()
        raise
    return sock


def start(port: int = 0) -> tuple[uvicorn.Server, threading.Thread, int]:
    """Start the server; port 0 picks a free one. Returns (server, thread, port)."""
    v4 = _bind(socket.AF_INET, "127.0.0.1", port)
    port = v4.getsockname()[1]
    sockets = [v4]
    try:
        sockets.append(_bind(socket.AF_INET6, "::1", port))
    except OSError:
        pass  # no IPv6 loopback (common in containers); localhost is 127.0.0.1 there

    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": sockets}, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        if not thread.is_alive() or time.time() > deadline:
            raise RuntimeError(f"mock server did not start on port {port}")
        time.sleep(0.05)
    return server, thread, port
