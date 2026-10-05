import socket

import pytest
from apidoc.curl import parse_curl
from apidoc.redact import MASK
from apidoc.runner import UnsafeRequestError, run
from apidoc.trace import Trace


def test_successful_get(live_server):
    trace = run(parse_curl(f"curl -H 'Authorization: Bearer good-token' {live_server}/v1/me"))
    assert trace.error is None
    assert len(trace.hops) == 1
    assert trace.final.status == 200
    assert trace.final.json_body() == {"user": "demo"}
    assert trace.final.elapsed_ms > 0 and trace.total_ms > 0


def test_records_headers_the_client_added(live_server):
    trace = run(parse_curl(f"curl {live_server}/v1/me"))
    sent = trace.final.request
    assert sent.header("user-agent").startswith("apidoc/")
    assert sent.header("host") is not None


def test_cross_host_redirect_drops_authorization(live_server):
    """The flagship bug: visible only by comparing hop 1 with hop 2."""
    trace = run(
        parse_curl(f"curl -L -H 'Authorization: Bearer good-token' {live_server}/v1/old-me")
    )
    assert [h.status for h in trace.hops] == [302, 401]
    first, last = trace.hops
    assert first.request.header("authorization") == "Bearer good-token"
    assert last.request.header("authorization") is None
    assert "localhost" in last.request.url  # different host name, same server


def test_without_follow_flag_redirect_is_not_followed(live_server):
    trace = run(parse_curl(f"curl -H 'Authorization: Bearer good-token' {live_server}/v1/old-me"))
    assert [h.status for h in trace.hops] == [302]
    assert trace.final.header("location").endswith("/v1/me")


def test_unsafe_method_is_refused_by_default(live_server):
    with pytest.raises(UnsafeRequestError, match="--allow-unsafe"):
        run(parse_curl(f"curl -X DELETE {live_server}/v1/me"))
    with pytest.raises(UnsafeRequestError):
        run(parse_curl(f"""curl -d '{{"a":1}}' {live_server}/v1/items"""))  # implicit POST


def test_unsafe_method_runs_when_allowed(live_server):
    trace = run(
        parse_curl(f"""curl -d '{{"name":"x"}}' {live_server}/v1/items"""), allow_unsafe=True
    )
    # curl's implicit form Content-Type -> the API rejects the "JSON" body.
    assert trace.final.status == 415
    assert trace.final.request.header("content-type") == "application/x-www-form-urlencoded"


def test_301_turns_post_into_get(live_server):
    trace = run(
        parse_curl(
            f"""curl -L -H 'Content-Type: application/json' -d '{{"a":1}}' """
            f"{live_server}/v1/old-items"
        ),
        allow_unsafe=True,
    )
    assert [(h.request.method, h.status) for h in trace.hops] == [("POST", 301), ("GET", 405)]
    assert trace.hops[1].request.body is None


def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]  # socket closes on exit: nothing listens here


def test_connection_refused_is_recorded_not_raised():
    trace = run(parse_curl(f"curl -m 10 http://127.0.0.1:{_closed_port()}/v1/me"))
    assert trace.hops == []
    assert trace.error_kind == "connect"
    assert trace.final is None


def test_large_bodies_are_truncated(live_server):
    trace = run(parse_curl(f"curl {live_server}/docs"), max_body_chars=50)
    assert trace.final.body_truncated
    assert len(trace.final.body) == 50


def test_redacted_trace_has_no_secret_and_round_trips(live_server):
    parsed = parse_curl(f"curl -L -H 'Authorization: Bearer s3cr3t-t0ken' {live_server}/v1/old-me")
    trace = run(parsed).redacted(parsed.redactor())
    text = trace.to_json()
    assert "s3cr3t-t0ken" not in text
    assert f"Bearer {MASK}" in text
    assert trace.is_redacted
    assert Trace.from_json(text) == trace
