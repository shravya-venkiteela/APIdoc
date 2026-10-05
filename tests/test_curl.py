import base64
import shlex
import string

import pytest
from apidoc.curl import CurlParseError, parse_curl
from apidoc.export import to_curl, to_httpx
from apidoc.models import Request
from hypothesis import given
from hypothesis import strategies as st

# parsing: what curl actually sends


def test_simple_get():
    p = parse_curl("curl https://api.test/v1/me")
    assert p.request.method == "GET"
    assert p.request.url == "https://api.test/v1/me"
    assert p.request.body is None


def test_headers_and_explicit_method():
    p = parse_curl("curl -X DELETE -H 'Authorization: Bearer abc123xyz' https://api.test/x")
    assert p.request.method == "DELETE"
    assert p.request.header("authorization") == "Bearer abc123xyz"


def test_data_implies_post_and_form_content_type():
    """The classic beginner bug: -d with JSON sends it as a form."""
    p = parse_curl("""curl https://api.test/items -d '{"name": "x"}'""")
    assert p.request.method == "POST"
    assert p.request.body == '{"name": "x"}'
    assert p.request.header("content-type") == "application/x-www-form-urlencoded"
    assert ("Content-Type", "application/x-www-form-urlencoded") in p.implicit_headers


def test_explicit_content_type_is_not_overridden():
    p = parse_curl(
        """curl -H 'Content-Type: application/json' -d '{"a":1}' https://api.test/items"""
    )
    assert p.request.header("content-type") == "application/json"
    assert p.implicit_headers == []


def test_json_flag():
    p = parse_curl("""curl --json '{"a":1}' https://api.test/items""")
    assert p.request.method == "POST"
    assert p.request.header("content-type") == "application/json"
    assert p.request.header("accept") == "application/json"


def test_multiple_data_flags_are_joined_with_ampersand():
    p = parse_curl("curl -d a=1 -d b=2 https://api.test/form")
    assert p.request.body == "a=1&b=2"


def test_get_flag_moves_data_to_query():
    p = parse_curl("curl -G -d q=cats -d page=2 'https://api.test/search?lang=en'")
    assert p.request.method == "GET"
    assert p.request.body is None
    assert p.request.url == "https://api.test/search?lang=en&q=cats&page=2"


def test_basic_auth_becomes_header_and_secret():
    p = parse_curl("curl -u admin:hunter22 https://api.test/x")
    token = base64.b64encode(b"admin:hunter22").decode()
    assert p.request.header("authorization") == f"Basic {token}"
    assert "hunter22" in p.secrets and token in p.secrets


def test_secrets_collected_from_headers_query_and_cookies():
    p = parse_curl(
        "curl -H 'Authorization: Bearer tok_abcdef12' -H 'X-Api-Key: key_99999999' "
        "-b 'sid=cookie_value1' 'https://api.test/x?api_key=query_secret1&page=2'"
    )
    for s in ["tok_abcdef12", "key_99999999", "cookie_value1", "query_secret1"]:
        assert s in p.secrets
    assert "2" not in p.secrets  # page=2 is not a credential


def test_flags_location_insecure_head_timeout():
    p = parse_curl("curl -L -k -I -m 5 https://api.test/x")
    assert p.follow_redirects and not p.verify_tls
    assert p.request.method == "HEAD"
    assert p.timeout == 5.0


def test_attached_short_flag_values():
    p = parse_curl("curl -XPUT -HAccept:text/plain https://api.test/x")
    assert p.request.method == "PUT"
    assert p.request.header("accept") == "text/plain"


@pytest.mark.parametrize("cont", ["\\\n", "^\n", "`\n", "\\\r\n"])
def test_line_continuations_bash_cmd_powershell(cont):
    p = parse_curl(f"curl -X POST {cont}  -H 'A: b' {cont}  https://api.test/x")
    assert p.request.method == "POST" and p.request.url == "https://api.test/x"


def test_curl_exe_and_missing_scheme():
    p = parse_curl("curl.exe localhost:8000/v1/me")
    assert p.request.url == "http://localhost:8000/v1/me"


def test_unknown_and_unsupported_flags_warn_but_do_not_fail():
    p = parse_curl("curl --frobnicate -s -o out.txt -F file=@a.png https://api.test/x")
    assert p.request.url == "https://api.test/x"
    assert any("--frobnicate" in w for w in p.warnings)
    assert any("multipart" in w for w in p.warnings)


@pytest.mark.parametrize(
    "bad", ["", "curl", "curl -H", "curl -H 'unclosed https://x", "curl -s -v"]
)
def test_errors(bad):
    with pytest.raises(CurlParseError):
        parse_curl(bad)


# exporting

header_name = st.text(alphabet=string.ascii_letters + "-", min_size=1, max_size=20).filter(
    lambda s: s[0].isalpha()
)
header_value = (
    st.text(
        alphabet=string.ascii_letters + string.digits + " ;=/.,'\"{}:-_", min_size=1, max_size=40
    )
    .map(str.strip)
    .filter(bool)
)
requests = st.builds(
    Request,
    method=st.sampled_from(["GET", "POST", "PUT", "PATCH", "DELETE"]),
    url=st.sampled_from(["https://api.test/v1/x", "http://localhost:8000/a?b=1&c=two"]),
    headers=st.lists(st.tuples(header_name, header_value), max_size=4),
    body=st.one_of(st.none(), st.text(alphabet=string.printable, min_size=1, max_size=60)),
)


@given(req=requests)
def test_curl_export_round_trips(req):
    """Export to curl, parse it back: same request (minus curl's implicit headers)."""
    parsed = parse_curl(to_curl(req))
    back = parsed.request
    implicit = set(parsed.implicit_headers)
    assert back.method == req.method
    assert back.url == req.url
    assert back.body == req.body
    assert [h for h in back.headers if h not in implicit] == req.headers


def test_powershell_export_quotes_single_quotes():
    req = Request(method="POST", url="https://api.test/x", body="it's")
    out = to_curl(req, shell="powershell")
    assert out.startswith("curl.exe")
    assert "'it''s'" in out


def test_httpx_export_is_runnable(monkeypatch):
    import httpx

    calls = {}

    def fake_request(method, url, **kwargs):
        calls.update(method=method, url=url, **kwargs)
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "request", fake_request)
    req = Request(
        method="POST",
        url="https://api.test/items",
        headers=[("Content-Type", "application/json")],
        body='{"a": 1}',
    )
    exec(compile(to_httpx(req, follow_redirects=True), "<export>", "exec"), {})
    assert calls["method"] == "POST"
    assert calls["content"] == '{"a": 1}'
    assert calls["headers"] == [("Content-Type", "application/json")]
    assert calls["follow_redirects"] is True


def test_data_from_file(tmp_path):
    f = tmp_path / "body.json"
    f.write_text('{\n  "a": 1\n}\n', encoding="utf-8")
    f = shlex.quote(f.as_posix())  # forward slashes: backslashes are escapes in curl syntax
    assert parse_curl(f"curl -d @{f} https://api.test/x").request.body == '{  "a": 1}'
    assert parse_curl(f"curl --data-binary @{f} https://api.test/x").request.body == (
        '{\n  "a": 1\n}\n'
    )
    # data-raw never reads files: the @ is literal.
    assert parse_curl("curl --data-raw @x https://api.test/x").request.body == "@x"


def test_missing_data_file_is_a_clear_error():
    with pytest.raises(CurlParseError, match="cannot read data file"):
        parse_curl("curl -d @does-not-exist.json https://api.test/x")
