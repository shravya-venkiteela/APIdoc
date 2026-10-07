import json
import string

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from apidoc.curl import parse_curl
from apidoc.diagnose import diagnose, ground
from apidoc.diagnosis import Category
from apidoc.llm import FakeProvider, LLMError
from apidoc.rules import Context
from apidoc.runner import run


def answer(category, evidence, summary="LLM summary.", fix="LLM fix.", confidence=0.8):
    return json.dumps(
        {
            "category": category,
            "summary": summary,
            "evidence": evidence,
            "fix": fix,
            "confidence": confidence,
        }
    )


def context_for(command: str) -> tuple[Context, object]:
    parsed = parse_curl(command)
    return Context(parsed, run(parsed, allow_unsafe=True)), parsed.redactor()


def test_prompt_contains_no_token(live_server):
    ctx, redactor = context_for(
        f"curl -L -H 'Authorization: Bearer sup3r-s3cret-tok3n' {live_server}/v1/old-me"
    )
    fake = FakeProvider([answer("auth_dropped_on_redirect", ["302 Found"])])
    diagnose(ctx, redactor, fake, mode="always")
    system, prompt = fake.prompts[0]
    assert "sup3r-s3cret-tok3n" not in prompt
    assert "Bearer [REDACTED]" in prompt  # scheme kept: it is evidence


SECRET = st.text(alphabet=string.ascii_letters + string.digits, min_size=12, max_size=40)


@given(secret=SECRET)
@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_no_secret_reaches_prompt_wherever_it_is(live_server, secret):
    """Secret in a header, the query string and a cookie at once."""
    ctx, redactor = context_for(
        f"curl -H 'X-Api-Key: {secret}' -b 'sid={secret}' '{live_server}/v1/keyed?api_key={secret}'"
    )
    fake = FakeProvider([answer("api_key_location", ["401"])])
    diagnose(ctx, redactor, fake, mode="always")
    assert secret not in fake.prompts[0][1]


def test_ground_is_verbatim_but_tolerant_of_case_and_spacing():
    kept, dropped = ground(
        ["HTTP/1.1   400 bad request", "made up fact"], "HTTP/1.1 400 Bad Request"
    )
    assert kept == ["HTTP/1.1   400 bad request"]
    assert dropped == ["made up fact"]


def test_vague_400_llm_wins_when_grounded(live_server):
    ctx, redactor = context_for(f"curl '{live_server}/v1/search?date_from=05/10/2026'")
    fake = FakeProvider(
        [
            answer(
                "bad_parameter",
                ["date_from=05/10/2026", '{"error":"invalid parameter"}'],
                summary="date_from is not in ISO 8601 format (YYYY-MM-DD).",
                fix="Send date_from=2026-10-05.",
                confidence=0.95,
            )
        ]
    )
    d, outcome = diagnose(ctx, redactor, fake, mode="auto")
    assert outcome.called and outcome.used
    assert d.source == "rules+llm"  # same category as the low-confidence rule
    assert "ISO 8601" in d.summary
    assert d.confidence <= 0.85


def test_invented_evidence_is_dropped_and_answer_discarded(live_server):
    ctx, redactor = context_for(f"curl '{live_server}/v1/search?date_from=05/10/2026'")
    fake = FakeProvider(
        [answer("not_found", ["the endpoint was removed in v2"], summary="Endpoint is gone.")]
    )
    d, outcome = diagnose(ctx, redactor, fake, mode="always")
    assert outcome.dropped_evidence == ["the endpoint was removed in v2"]
    assert not outcome.used
    assert d.category == Category.BAD_PARAMETER and d.source == "rules"


def test_llm_takes_over_when_no_rule_matched(live_server):
    """/v1/meee is a 404; pretend the LLM spots the typo with grounded evidence."""
    ctx, redactor = context_for(f"curl {live_server}/v1/meee")
    fake = FakeProvider([answer("not_found", ["/v1/meee"], summary="Typo: did you mean /v1/me?")])
    d, outcome = diagnose(ctx, redactor, fake, mode="always")
    assert outcome.used
    assert "Typo" in d.summary


def test_strong_rule_beats_disagreeing_llm(live_server):
    ctx, redactor = context_for(f"curl {live_server}/v1/limited")
    fake = FakeProvider([answer("server_error", ["429"], summary="Server is down.")])
    d, outcome = diagnose(ctx, redactor, fake, mode="always")
    assert d.category == Category.RATE_LIMITED
    assert "kept the rule" in outcome.reason


def test_auto_mode_skips_llm_when_rules_are_confident(live_server):
    ctx, redactor = context_for(f"curl {live_server}/v1/limited")
    fake = FakeProvider([])
    d, outcome = diagnose(ctx, redactor, fake, mode="auto")
    assert fake.prompts == [] and not outcome.called
    assert d.category == Category.RATE_LIMITED


def test_agreeing_llm_rewrites_explanation_keeps_fix(live_server):
    ctx, redactor = context_for(f"""curl -d '{{"name": "x"}}' {live_server}/v1/items""")
    fake = FakeProvider(
        [answer("content_type", ["415"], summary="Plain-English explanation.", confidence=0.9)]
    )
    d, outcome = diagnose(ctx, redactor, fake, mode="always")
    assert d.source == "rules+llm"
    assert d.summary == "Plain-English explanation."
    assert d.fixed_request is not None  # the rule's machine-applicable fix survives


def test_invalid_json_retried_once_then_falls_back(live_server):
    ctx, redactor = context_for(f"curl {live_server}/v1/meee")
    fake = FakeProvider(["not json", "still not json"])
    d, outcome = diagnose(ctx, redactor, fake, mode="always")
    assert len(fake.prompts) == 2
    assert "invalid JSON twice" in outcome.reason
    assert d.source == "rules"


def test_fenced_json_is_accepted(live_server):
    ctx, redactor = context_for(f"curl {live_server}/v1/meee")
    fake = FakeProvider(["```json\n" + answer("not_found", ["/v1/meee"]) + "\n```"])
    _, outcome = diagnose(ctx, redactor, fake, mode="always")
    assert outcome.used


def test_provider_error_falls_back_to_rules(live_server):
    def boom(system, prompt):
        raise LLMError("quota exhausted")

    ctx, redactor = context_for(f"curl {live_server}/v1/meee")
    d, outcome = diagnose(ctx, redactor, FakeProvider(boom), mode="always")
    assert d.category == Category.NOT_FOUND
    assert "quota exhausted" in outcome.reason


def test_llm_echoing_a_secret_is_redacted(live_server):
    """Defence in depth: even if the model repeats a secret, it is masked."""
    ctx, redactor = context_for(
        f"curl -H 'Authorization: Bearer leaky-t0ken-value' {live_server}/v1/meee"
    )
    fake = FakeProvider(
        [answer("not_found", ["/v1/meee"], fix="Retry with leaky-t0ken-value on /v1/me.")]
    )
    d, _ = diagnose(ctx, redactor, fake, mode="always")
    assert "leaky-t0ken-value" not in d.model_dump_json()


def test_no_rule_finding_cannot_overrule_the_llm(live_server):
    """Regression from the eval (h05): SSO redirect ends on a 200 HTML login page.

    No rule fires, so the rules' verdict is the fallback "ok". That absence of
    findings must not overrule an LLM that spotted the login page.
    """
    ctx, redactor = context_for(f"curl -L {live_server}/v1/sso-report")
    fake = FakeProvider(
        [
            answer(
                "auth_missing",
                ["Sign in - Example SSO"],
                summary="You were redirected to a login page: the request had no session.",
            )
        ]
    )
    d, outcome = diagnose(ctx, redactor, fake, mode="auto")
    assert outcome.called, "auto mode must consult the LLM when rules only say 'ok'"
    assert d.category == Category.AUTH_MISSING
    assert d.source == "llm"


def test_a_real_rule_finding_still_overrules(live_server):
    """The other overrule from the eval (b03) was correct and must stay."""
    ctx, redactor = context_for(
        f"curl -H 'Authorization: Bearer Bearer good-token' {live_server}/v1/me"
    )
    fake = FakeProvider([answer("auth_invalid", ["401"], summary="Bad token.")])
    d, outcome = diagnose(ctx, redactor, fake, mode="always")
    assert d.category == Category.AUTH_SCHEME
    assert "kept the rule" in outcome.reason


def test_merge_evidence_drops_rewordings_of_the_same_fact():
    from apidoc.diagnose import merge_evidence

    rules = ["response: 400 Bad Request", 'response body: {"error":"invalid parameter"}']
    llm = ["HTTP/1.1 400 Bad Request", '{"error": "invalid parameter"}', "date_from=05/10/2026"]
    assert merge_evidence(rules, llm) == [*rules, "date_from=05/10/2026"]


def test_merge_evidence_keeps_different_facts_with_the_same_value():
    from apidoc.diagnose import merge_evidence

    items = ["request body: {}", "response body: {}"]
    assert merge_evidence(items) == items


def test_auto_skips_the_llm_for_a_clean_json_success(live_server):
    ctx, redactor = context_for(f"curl -H 'Authorization: Bearer good-token' {live_server}/v1/me")
    provider = FakeProvider([])  # any call would raise "ran out of responses"
    d, outcome = diagnose(ctx, redactor, provider, mode="auto")
    assert d.category == Category.OK
    assert provider.prompts == []
    assert not outcome.called


def test_auto_still_asks_the_llm_about_a_200_html_page_after_a_redirect(live_server):
    ctx, redactor = context_for(f"curl -L {live_server}/v1/sso-report")
    provider = FakeProvider([answer("auth_missing", ["Sign in - Example SSO"])])
    d, outcome = diagnose(ctx, redactor, provider, mode="auto")
    assert outcome.called
    assert d.category == Category.AUTH_MISSING
