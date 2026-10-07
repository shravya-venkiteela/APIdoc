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


def test_replay_is_deterministic_across_runs(live_server, tmp_path):
    """Recordings must keep matching even though every run mints new random
    tokens (jti) and the server sends a new Date header."""
    from apidoc.llm import LLMError

    cases = [
        {**c, "expect": c["expect"]}
        for c in json.loads((run_eval.HERE / "cases.json").read_text(encoding="utf-8"))["cases"]
        if c["id"] in ("e01", "e03", "e04", "e06", "e07", "h05")
    ]
    answer = json.dumps(
        {"category": "unknown", "summary": "x", "evidence": ["HTTP/1.1"], "fix": "y",
         "confidence": 0.1}
    )  # fmt: skip

    def live_call(system, prompt):
        raise LLMError("live call during replay")

    recorder = CachedProvider(
        FakeProvider(lambda s, p: answer), tmp_path, mode="record", normalize=run_eval.normalize
    )
    run_eval.evaluate(cases, live_server, recorder)
    replayer = CachedProvider(
        FakeProvider(live_call), tmp_path, mode="replay", normalize=run_eval.normalize
    )
    results = run_eval.evaluate(cases, live_server, replayer)
    assert replayer.cache_hits == len(cases)
    assert not any(r.llm_error for r in results)


def test_failed_llm_call_is_not_credited_to_the_llm(live_server, tmp_path):
    """A failed call makes diagnose() fall back to the rules. That fallback must
    not be scored as an LLM success, or the LLM column is inflated."""
    from apidoc.llm import LLMError

    def down(system, prompt):
        raise LLMError("simulated outage")

    provider = CachedProvider(FakeProvider(down), tmp_path, mode="live")
    results = {r.id: r for r in run_eval.evaluate(CASES, live_server, provider)}
    for r in results.values():
        assert r.llm_error
        assert not r.llm.diagnosed
        assert r.auto == r.rules  # users get the rules' answer when the LLM is down


def test_normalize_makes_os_socket_errors_identical():
    """Recorded on Windows, replayed on Linux CI: the cache key must match."""
    windows = (
        "no response: connect: [WinError 10061] No connection could be made because the "
        "target machine actively refused it\n    evidence: connection error: [WinError 10061] x"
    )
    linux = (
        "no response: connect: [Errno 111] Connection refused\n"
        "    evidence: connection error: [Errno 111] Connection refused"
    )
    assert run_eval.normalize(windows) == run_eval.normalize(linux)
