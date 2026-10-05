from datetime import UTC, datetime, timedelta

import pytest

from apidoc.curl import ParsedCurl, parse_curl
from apidoc.diagnosis import Category, Diagnosis
from apidoc.models import Request
from apidoc.rules import Context, diagnose_with_rules
from apidoc.runner import run
from apidoc.trace import Hop, Trace
from mock_server import tokens


def diagnose(command: str) -> Diagnosis:
    parsed = parse_curl(command)
    return diagnose_with_rules(Context(parsed, run(parsed, allow_unsafe=True)))


def assert_fix_works(d: Diagnosis, follow_redirects: bool = False) -> None:
    assert d.fixed_request is not None, "rule should propose a machine-applicable fix"
    trace = run(
        ParsedCurl(request=d.fixed_request, follow_redirects=follow_redirects),
        allow_unsafe=True,
    )
    assert trace.final is not None and trace.final.status < 300, trace.final


def test_auth_missing(live_server):
    d = diagnose(f"curl {live_server}/v1/me")
    assert d.category == Category.AUTH_MISSING
    assert d.fixed_request.header("authorization") == "Bearer <YOUR_TOKEN>"


def test_api_key_missing_names_the_header(live_server):
    d = diagnose(f"curl {live_server}/v1/keyed")
    assert d.category == Category.AUTH_MISSING
    assert "X-API-Key" in d.summary


def test_token_without_bearer_prefix(live_server):
    d = diagnose(f"curl -H 'Authorization: good-token' {live_server}/v1/me")
    assert d.category == Category.AUTH_SCHEME
    assert_fix_works(d)


def test_double_bearer(live_server):
    d = diagnose(f"curl -H 'Authorization: Bearer Bearer good-token' {live_server}/v1/me")
    assert d.category == Category.AUTH_SCHEME
    assert_fix_works(d)


def test_expired_jwt(live_server):
    token = tokens.mint(ttl=-7200)
    d = diagnose(f"curl -H 'Authorization: Bearer {token}' {live_server}/v1/me")
    assert d.category == Category.AUTH_EXPIRED
    assert any("ago" in e for e in d.evidence)


def test_jwt_not_yet_valid(live_server):
    token = tokens.mint(nbf_offset=3600)
    d = diagnose(f"curl -H 'Authorization: Bearer {token}' {live_server}/v1/me")
    assert d.category == Category.AUTH_NOT_YET_VALID


def test_insufficient_scope(live_server):
    d = diagnose(f"curl -H 'Authorization: Bearer good-token' {live_server}/v1/admin/users")
    assert d.category == Category.AUTH_SCOPE
    assert "admin" in d.summary
    assert d.confidence >= 0.9


def test_scope_claim_shown_for_jwt(live_server):
    token = tokens.mint(scope="read write")
    d = diagnose(f"curl -H 'Authorization: Bearer {token}' {live_server}/v1/admin/users")
    assert any("read write" in e for e in d.evidence)


def test_wrong_token(live_server):
    d = diagnose(f"curl -H 'Authorization: Bearer not-a-real-token' {live_server}/v1/me")
    assert d.category == Category.AUTH_INVALID


def test_auth_dropped_on_cross_host_redirect(live_server):
    d = diagnose(f"curl -L -H 'Authorization: Bearer good-token' {live_server}/v1/old-me")
    assert d.category == Category.AUTH_DROPPED_ON_REDIRECT
    assert d.confidence >= 0.9
    assert_fix_works(d)


def test_api_key_in_query_string(live_server):
    d = diagnose(f"curl '{live_server}/v1/keyed?api_key=good-key'")
    assert d.category == Category.API_KEY_LOCATION
    assert d.fixed_request.header("x-api-key") == "good-key"
    assert "api_key" not in d.fixed_request.url
    assert_fix_works(d)


def test_json_sent_as_form_by_curl_d(live_server):
    d = diagnose(f"""curl -d '{{"name": "x"}}' {live_server}/v1/items""")
    assert d.category == Category.CONTENT_TYPE
    assert any("curl added" in e for e in d.evidence)
    assert_fix_works(d)


def test_malformed_json_hints_at_powershell(live_server):
    d = diagnose(
        f"curl -H 'Content-Type: application/json' -d '{{name: x}}' {live_server}/v1/items"
    )
    assert d.category == Category.MALFORMED_BODY
    assert "PowerShell" in d.fix


def test_validation_errors_are_listed(live_server):
    d = diagnose(f"""curl --json '{{"email": "a@b.c"}}' {live_server}/v1/users""")
    assert d.category == Category.VALIDATION
    assert "age" in d.summary


def test_post_turned_into_get_by_301(live_server):
    d = diagnose(f"""curl -L --json '{{"a": 1}}' {live_server}/v1/old-items""")
    assert d.category == Category.METHOD_CHANGED_ON_REDIRECT
    assert_fix_works(d)


def test_method_not_allowed_names_allowed_method(live_server):
    d = diagnose(f"curl {live_server}/v1/items")
    assert d.category == Category.METHOD_NOT_ALLOWED
    assert "POST" in d.summary
    # No automatic fix: a POST without the body the endpoint needs would fail too.
    assert d.fixed_request is None


def test_not_found(live_server):
    d = diagnose(f"curl {live_server}/v1/meee")
    assert d.category == Category.NOT_FOUND


def test_not_acceptable(live_server):
    d = diagnose(f"curl -H 'Accept: text/csv' {live_server}/v1/report")
    assert d.category == Category.NOT_ACCEPTABLE
    assert_fix_works(d)


def test_vague_400_is_low_confidence(live_server):
    """Rules cannot name this cause; they must say so, not guess confidently."""
    d = diagnose(f"curl '{live_server}/v1/search?date_from=05/10/2026'")
    assert d.category == Category.BAD_PARAMETER
    assert d.confidence < 0.5


def test_rate_limited(live_server):
    d = diagnose(f"curl {live_server}/v1/limited")
    assert d.category == Category.RATE_LIMITED
    assert "retry-after: 30" in d.evidence


def test_error_inside_200(live_server):
    d = diagnose(f"curl {live_server}/v1/quota")
    assert d.category == Category.ERROR_IN_SUCCESS
    assert any("QUOTA_EXCEEDED" in e for e in d.evidence)


def test_server_error(live_server):
    assert diagnose(f"curl {live_server}/v1/broken").category == Category.SERVER_ERROR


def test_connection_refused():
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    assert diagnose(f"curl -m 10 http://127.0.0.1:{port}/").category == Category.CONNECTION


def test_success_is_ok(live_server):
    d = diagnose(f"curl -H 'Authorization: Bearer good-token' {live_server}/v1/me")
    assert d.category == Category.OK


def test_clock_skew_reported_from_date_header():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    token = tokens.mint(nbf_offset=0, now=(now + timedelta(minutes=20)).timestamp())
    parsed = parse_curl(f"curl -H 'Authorization: Bearer {token}' https://api.test/v1/me")
    hop = Hop(
        request=parsed.request,
        status=401,
        reason="Unauthorized",
        headers=[("Date", "Thu, 01 Jan 2026 12:20:00 GMT")],  # server is 20 min ahead
    )
    d = diagnose_with_rules(Context(parsed, Trace(hops=[hop]), now=now))
    assert d.category == Category.AUTH_NOT_YET_VALID
    assert "Clock skew" in d.summary


@pytest.mark.parametrize("path", ["/v1/old-me", "/v1/me"])
def test_redacted_diagnosis_contains_no_token(live_server, path):
    parsed = parse_curl(f"curl -L -H 'Authorization: s3cret-tok3n-value' {live_server}{path}")
    d = diagnose_with_rules(Context(parsed, run(parsed))).redacted(parsed.redactor())
    assert "s3cret-tok3n-value" not in d.model_dump_json()


def test_patch_apply_replaces_header_case_insensitively():
    from apidoc.diagnosis import Patch

    req = Request(url="http://x", headers=[("authorization", "old"), ("A", "1")])
    out = Patch(set_headers=[("Authorization", "new")]).apply(req)
    assert out.headers == [("A", "1"), ("Authorization", "new")]
