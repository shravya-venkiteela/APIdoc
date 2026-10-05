import json

from apidoc.llm import CachedProvider, FakeProvider
from evals import run_eval

CASES = [
    {
        "id": "x1",
        "audience": "hard",
        "title": "plain-string 400",
        "curl": "curl '{base}/v1/list?page_size=500'",
        "expect": {"category": "bad_parameter", "mentions": ["page_size"]},
    },
    {
        "id": "x2",
        "audience": "experienced",
        "title": "rate limited",
        "curl": "curl {base}/v1/limited",
        "expect": {"category": "rate_limited", "mentions": ["retry"]},
    },
    {
        "id": "x3",
        "audience": "beginner",
        "title": "json body in a curl -d with braces",
        "curl": 'curl -d \'{"name": "x"}\' {base}/v1/items',
        "allow_unsafe": True,
        "expect": {"category": "content_type", "mentions": ["application/json"]},
    },
]


def oracle(system: str, prompt: str) -> str:
    if "/v1/list" in prompt:
        return json.dumps(
            {
                "category": "bad_parameter",
                "summary": "page_size is above the maximum.",
                "evidence": ["page_size must be <= 100"],
                "fix": "Use page_size=100 or less.",
                "confidence": 0.9,
            }
        )
    # Disagrees with everything else: proven rules must win.
    return json.dumps(
        {
            "category": "unknown",
            "summary": "No idea.",
            "evidence": ["HTTP/1.1"],
            "fix": "Check the docs.",
            "confidence": 0.4,
        }
    )


def test_eval_scores_rules_llm_and_auto(live_server, tmp_path):
    provider = CachedProvider(FakeProvider(oracle), tmp_path, mode="record")
    results = {r.id: r for r in run_eval.evaluate(CASES, live_server, provider)}

    hard = results["x1"]
    assert not hard.rules.diagnosed
    assert hard.llm.diagnosed
    assert hard.auto.diagnosed

    limited = results["x2"]
    assert limited.rules.diagnosed and limited.auto.diagnosed
    assert "kept the rule" in limited.llm_note

    assert results["x3"].fix_works is True  # placeholder filling left the JSON intact


def test_report_renders(live_server, tmp_path):
    provider = CachedProvider(FakeProvider(oracle), tmp_path, mode="record")
    results = run_eval.evaluate(CASES, live_server, provider)
    md = run_eval.report(results, "fake-1", "record")
    assert "| hard | 0/1 (0%) | 1/1 (100%) | 1/1 (100%) |" in md


def test_normalize_removes_volatile_values():
    a = "date: Mon, 05 Oct 2026 10:00:00 GMT; expired 5 hours ago at 2026-10-05 05:00:00 UTC"
    b = "date: Tue, 06 Oct 2026 11:30:00 GMT; expired 6 hours ago at 2026-10-06 05:30:00 UTC"
    assert run_eval.normalize(a) == run_eval.normalize(b)
