import base64
import json
import string

from hypothesis import given, settings
from hypothesis import strategies as st

from apidoc.redact import MASK, Redactor

# Secrets: 8-48 characters of the alphabet real tokens use.
SECRET_CHARS = string.ascii_letters + string.digits + "-_."
secrets = st.text(alphabet=SECRET_CHARS, min_size=8, max_size=48).filter(
    lambda s: s not in MASK and not s.strip("-_.") == ""
)
# Surrounding text: anything printable.
noise = st.text(alphabet=string.printable, max_size=80)


# known values


@given(secret=secrets, before=noise, after=noise)
@settings(max_examples=500)
def test_known_secret_never_survives_in_free_text(secret, before, after):
    r = Redactor([secret])
    out = r.text(before + secret + after)
    assert secret not in out


@given(secret=secrets)
def test_known_secret_masked_when_url_encoded_or_base64(secret):
    r = Redactor([secret])
    b64 = base64.b64encode(secret.encode()).decode()
    assert b64 not in r.text(f"Authorization: Basic {b64}")
    assert secret not in r.text(f"https://api.example.com/x?q={secret}")


@given(user=st.text(alphabet=string.ascii_letters, min_size=1, max_size=12), pw=secrets)
def test_basic_auth_base64_is_masked(user, pw):
    r = Redactor()
    r.add_basic_auth(user, pw)
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    assert token not in r.text(f"-H 'Authorization: Basic {token}'")


@given(secret=secrets, before=noise, after=noise)
def test_redaction_is_idempotent(secret, before, after):
    r = Redactor([secret])
    once = r.text(before + secret + after)
    assert r.text(once) == once


# unknown values, caught by pattern


@given(secret=secrets)
@settings(max_examples=300)
def test_unknown_secret_in_sensitive_places(secret):
    """No known values registered: the patterns alone must catch these.

    A random secret can collide with ordinary text in the template (secret
    "Authoriz" is inside the header name "Authorization"), so the check is:
    the secret appears no more often than in the template without it.
    """
    r = Redactor()
    templates = [
        "curl -H 'Authorization: Bearer {s}' https://x.test",
        "https://x.test/v1?api_key={s}&page=2",
        "https://x.test/v1?page=2&access_token={s}",
        "https://user:{s}@x.test/v1",
        "curl -u admin:{s} https://x.test",
        "client_secret={s}&grant_type=client_credentials",
        '{{"password": "{s}", "user": "a"}}',
        "Cookie: session={s}",
    ]
    for template in templates:
        place = template.format(s=secret)
        allowed = template.format(s="").count(secret)
        assert r.text(place).count(secret) <= allowed, place


@given(secret=secrets)
def test_sensitive_headers_masked_whatever_the_value(secret):
    r = Redactor()
    out = dict(r.headers({"X-Api-Key": secret, "Authorization": f"Bearer {secret}"}))
    assert out["X-Api-Key"] == MASK
    assert out["Authorization"] == f"Bearer {MASK}"  # scheme kept as evidence


@given(secret=secrets)
def test_json_bodies_masked_by_key_name_at_any_depth(secret):
    r = Redactor()
    body = {"data": [{"auth": {"refresh_token": secret}}], "client_secret": secret, "n": 1}
    out = json.dumps(r.json(body))
    skeleton = json.dumps({"data": [{"auth": {"refresh_token": ""}}], "client_secret": "", "n": 1})
    assert out.count(secret) <= skeleton.count(secret)  # see collision note above
    assert '"n": 1' in out  # non-secret data untouched


def test_jwt_pattern():
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNzAwMDAwMDAwfQ."
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    assert jwt not in Redactor().text(f"token was {jwt} in the log")


def test_provider_prefixes():
    r = Redactor()
    for token in [
        "ghp_" + "a" * 36,
        "github_pat_" + "B" * 30,
        "xoxb-1234567890-abcdefghij",
        "AIza" + "x" * 35,
        "AKIA" + "ABCDEFGHIJKLMNOP",
        "sk_live_" + "z" * 24,
    ]:
        assert token not in r.text(f"leaked {token} here"), token


def test_set_cookie_keeps_name_and_attributes():
    r = Redactor()
    out = r.header_value("Set-Cookie", "sid=abc123secret; Path=/; HttpOnly")
    assert out == f"sid={MASK}; Path=/; HttpOnly"


def test_cookie_header_masks_every_value():
    out = Redactor().header_value("Cookie", "sid=abc123; theme=dark")
    assert "abc123" not in out and "dark" not in out
    assert out.startswith("sid=")


# no false positives on ordinary data
def test_ordinary_text_untouched():
    r = Redactor()
    for text in [
        "GET /v1/me HTTP/1.1",
        "Content-Type: application/json",
        '{"user": "demo", "items": [1, 2, 3]}',
        "https://api.example.com/v1/items?page=2&sort=asc",
        "The token endpoint returned 401",
        "Use the Bearer scheme for this API",
        "Authorization header was missing",
    ]:
        assert r.text(text) == text, text


def test_error_codes_and_lookalike_keys_survive():
    # Error codes are the evidence the diagnosis needs; "author" is not "auth".
    body = {"error": {"code": "INVALID_ARGUMENT", "message": "bad date"}, "author": "sam"}
    assert Redactor().json(body) == body
    assert Redactor().text("?author=sam&page=2") == "?author=sam&page=2"


def test_short_values_are_not_registered():
    # Masking "ab" everywhere would destroy the trace and protect nothing.
    r = Redactor(["ab", ""])
    assert r.known_count == 0
