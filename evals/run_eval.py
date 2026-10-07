"""Evaluate APIdoc: rules only vs LLM vs the shipped "auto" pipeline.

    python evals/run_eval.py                    # rules only, no API key needed
    python evals/run_eval.py --llm record       # call Gemini once per case, save responses
    python evals/run_eval.py --llm replay       # re-score from saved responses, zero API calls

A case is "diagnosed" only if the category is right AND the explanation names
the actual cause (one of the case's `mentions` keywords). Category alone is
too easy: "bad_parameter" for a vague 400 is correct but tells the user
nothing they did not already know.

Results go to evals/results.md (for humans) and evals/results.json.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from apidoc.curl import ParsedCurl, parse_curl
from apidoc.diagnose import STRONG_RULE, LLMOutcome, diagnose
from apidoc.diagnosis import Diagnosis
from apidoc.llm import CachedProvider, GeminiProvider, LLMError
from apidoc.rules import Context
from apidoc.runner import run
from mock_server import serve, tokens

HERE = Path(__file__).resolve().parent
EXPIRED_AGO_S = 3600  # e03: expired one hour ago
SKEW_AHEAD_S = 210  # e04: issuer clock 3.5 min fast; 30 s leeway, so clearly rejected


def placeholders(base: str) -> dict[str, str]:
    now = time.time()
    read_jwt = tokens.mint(scope="read", ttl=3600, now=now)
    return {
        "base": base,
        "closed": "http://127.0.0.1:9",  # discard port: nothing listens there
        "expired_jwt": tokens.mint(ttl=-EXPIRED_AGO_S, now=now),
        # Issued by a server whose clock runs ahead: iat and nbf are in our future.
        "future_jwt": tokens.mint(now=now + SKEW_AHEAD_S),
        "read_jwt": read_jwt,
        "tampered_jwt": read_jwt.rsplit(".", 1)[0] + "." + "A" * 43,
    }


def fill(template: str, values: dict[str, str]) -> str:
    """Replace {name} placeholders only; JSON braces in bodies are left alone."""
    for name, value in values.items():
        template = template.replace("{" + name + "}", value)
    return template


_VOLATILE = [
    (re.compile(r"[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT"), "<date>"),
    (re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC"), "<timestamp>"),
    (re.compile(r"\b\d+ (second|minute|hour|day)s?\b"), r"<n> \1s"),
]


def normalize(prompt: str) -> str:
    for pattern, replacement in _VOLATILE:
        prompt = pattern.sub(replacement, prompt)
    return prompt


def start_mock(port: int):
    try:
        server, _thread, _port = serve.start(port)
    except (OSError, RuntimeError) as exc:
        raise SystemExit(f"mock server could not start on port {port} (in use?): {exc}") from exc
    return server


@dataclass
class Score:
    category: str
    category_ok: bool
    cause_named: bool
    confidence: float
    source: str
    summary: str

    @property
    def diagnosed(self) -> bool:
        return self.category_ok and self.cause_named


@dataclass
class CaseResult:
    id: str
    audience: str
    title: str
    expected: str
    rules: Score
    auto: Score
    llm: Score | None = None
    llm_note: str = ""
    llm_error: bool = False
    dropped_evidence: int = 0
    fix_works: bool | None = None  # None: the rules proposed no applicable fix
    notes: list[str] = field(default_factory=list)


def score(d: Diagnosis, expect: dict) -> Score:
    text = f"{d.summary} {d.fix}".lower()
    named = any(m.lower() in text for m in expect["mentions"])
    return Score(
        category=d.category.value,
        category_ok=d.category.value == expect["category"],
        cause_named=named,
        confidence=round(d.confidence, 2),
        source=d.source,
        summary=d.summary,
    )


def fix_works(d: Diagnosis, follow: bool) -> bool | None:
    req = d.fixed_request
    if req is None or any("<YOUR_" in v for _, v in req.headers):
        return None
    trace = run(ParsedCurl(request=req, follow_redirects=follow), allow_unsafe=True)
    return trace.final is not None and trace.final.status < 300


def evaluate(cases: list[dict], base: str, provider) -> list[CaseResult]:
    results = []
    for case in cases:
        # Mint per case: with a throttled live LLM, later cases run minutes later.
        parsed = parse_curl(fill(case["curl"], placeholders(base)))
        trace = run(parsed, allow_unsafe=case.get("allow_unsafe", False))
        ctx = Context(parsed, trace)
        redactor = parsed.redactor()
        expect = case["expect"]

        rules_d, _ = diagnose(ctx, redactor, None, mode="never")
        result = CaseResult(
            id=case["id"],
            audience=case["audience"],
            title=case["title"],
            expected=expect["category"],
            rules=score(rules_d, expect),
            auto=score(rules_d, expect),
        )
        # Re-diagnose unredacted to test the fix (the redacted one has [REDACTED] tokens).
        raw_d, _ = diagnose(ctx, _NoRedaction(), None, mode="never")
        result.fix_works = fix_works(raw_d, parsed.follow_redirects)

        if provider is not None:
            llm_d, outcome = diagnose(ctx, redactor, provider, mode="always")
            result.llm_note = outcome.reason
            result.llm_error = outcome.answer is None or "discarded" in outcome.reason
            result.dropped_evidence = len(outcome.dropped_evidence)
            if result.llm_error:
                # No usable LLM answer (call failed, invalid JSON, or ungrounded).
                # diagnose() fell back to the rules; crediting that to the LLM
                # column would inflate it, so it counts as not diagnosed.
                result.llm = Score("error", False, False, 0.0, "error", outcome.reason)
            else:
                result.llm = score(llm_d, expect)
            # "auto" = what users get: the LLM is only consulted when rules are unsure,
            # and when it fails they get the rules' answer.
            if rules_d.confidence < STRONG_RULE and not result.llm_error:
                result.auto = result.llm
            _print_progress(result, outcome)
        else:
            _print_progress(result, None)
        results.append(result)
    return results


class _NoRedaction:
    def text(self, value):
        return value

    def headers(self, headers):
        return list(headers.items() if hasattr(headers, "items") else headers)

    def json(self, obj):
        return obj


def _print_progress(r: CaseResult, outcome: LLMOutcome | None) -> None:
    mark = "ok " if r.rules.diagnosed else "-- "
    line = f"  {r.id} rules:{mark}"
    if r.llm is not None:
        line += f" llm:{'ERR' if r.llm_error else ('ok ' if r.llm.diagnosed else '-- ')}"
    reason = f"  [{r.llm_note}]" if r.llm_error else ""
    print(f"{line} {r.title}{reason}", flush=True)


def pct(n: int, d: int) -> str:
    return f"{n}/{d} ({100 * n // d}%)" if d else "-"


def report(results: list[CaseResult], model: str | None, mode: str) -> str:
    groups = ["beginner", "experienced", "hard"]
    has_llm = any(r.llm is not None for r in results)
    lines = [
        "# APIdoc eval results",
        "",
        f"- Cases: {len(results)} ({', '.join(f'{g}: {sum(r.audience == g for r in results)}' for g in groups)})",  # noqa: E501
        f"- LLM: {model + f' ({mode})' if has_llm else 'not run (rules only)'}",
        "",
        "**Diagnosed** = right category AND the explanation names the actual cause.",
        "**auto** = the shipped behaviour: the LLM is consulted only when the rules'",
        f"confidence is below {STRONG_RULE}.",
        "",
        "## Summary",
        "",
    ]
    header = "| Cases | Rules only | " + ("LLM always | Auto (shipped) |" if has_llm else "")
    lines += [header, "|---|---|" + ("---|---|" if has_llm else "")]
    for name, subset in [*[(g, [r for r in results if r.audience == g]) for g in groups],
                         ("**all**", results)]:  # fmt: skip
        n = len(subset)
        row = f"| {name} | {pct(sum(r.rules.diagnosed for r in subset), n)} |"
        if has_llm:
            row += f" {pct(sum(bool(r.llm and r.llm.diagnosed) for r in subset), n)} |"
            row += f" {pct(sum(r.auto.diagnosed for r in subset), n)} |"
        lines.append(row)

    fixes = [r.fix_works for r in results if r.fix_works is not None]
    lines += [
        "",
        f"Machine-applied fixes that made the request succeed: {pct(sum(fixes), len(fixes))}",
    ]
    if has_llm:
        errors = sum(r.llm_error for r in results)
        discarded = sum("discarded" in r.llm_note for r in results)
        kept_rule = sum("kept the rule" in r.llm_note for r in results)
        lines += [
            f"LLM gave no usable answer (failed call, invalid JSON, ungrounded): {errors}"
            " (counted as not diagnosed in the LLM column)",
            f"  of which discarded for ungrounded evidence: {discarded}",
            f"LLM disagreements overruled by a proven rule: {kept_rule}",
            f"Evidence items dropped by the grounding check: "
            f"{sum(r.dropped_evidence for r in results)}",
        ]

    lines += ["", "## Per case", ""]
    cols = "| id | case | expected | rules |" + (" llm | auto |" if has_llm else "")
    lines += [cols, "|---|---|---|---|" + ("---|---|" if has_llm else "")]

    def cell(s: Score | None) -> str:
        if s is None:
            return "-"
        mark = "PASS" if s.diagnosed else ("PARTIAL" if s.category_ok else "FAIL")
        return f"{mark} {s.category} ({s.confidence:.2f})"

    for r in results:
        row = f"| {r.id} | {r.title} | {r.expected} | {cell(r.rules)} |"
        if has_llm:
            row += f" {cell(r.llm)} | {cell(r.auto)} |"
        lines.append(row)
    lines += [
        "",
        "PASS = diagnosed; PARTIAL = right category, cause not named; FAIL = wrong category",
        "",
        "## Limitations",
        "",
        "- The cases are self-authored against a self-built mock API. The 'hard' cases",
        "  were written so that no rule matches them, which is the only part of this",
        "  eval that can show the LLM adding value; it is still small (5 cases).",
        "- 'Cause named' is a keyword check, not a judgement of explanation quality.",
        "- One LLM sample per case. Recorded responses make reruns reproducible, but",
        "  a fresh recording can score differently.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate APIdoc: rules vs LLM vs auto.")
    ap.add_argument("--cases", type=Path, default=HERE / "cases.json")
    ap.add_argument("--llm", choices=["none", "replay", "record", "live"], default="none")
    ap.add_argument("--cache", type=Path, default=HERE / "llm_cache")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument(
        "--min-interval",
        type=float,
        default=6.0,
        help="seconds between live LLM calls (free tier is ~10-15 requests/minute)",
    )
    ap.add_argument("--only", help="comma-separated case ids, for debugging one case")
    ap.add_argument(
        "--prune", action="store_true", help="delete recordings no case used (replay/record)"
    )
    args = ap.parse_args(argv)
    if args.prune and (args.only or args.llm not in ("replay", "record")):
        ap.error("--prune needs --llm replay or record, over all cases (no --only)")
    cases = json.loads(args.cases.read_text(encoding="utf-8"))["cases"]
    if args.only:
        wanted = set(args.only.split(","))
        cases = [c for c in cases if c["id"] in wanted]

    provider = None
    model = None
    if args.llm != "none":
        try:
            if args.llm == "replay":
                inner = _ReplayOnly()
            else:
                # Same lookup as the CLI: GEMINI_API_KEY, else the keyring.
                from apidoc.cli import _gemini_key

                key, source = _gemini_key()
                inner = GeminiProvider(key or "", key_source=source)
        except LLMError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        provider = CachedProvider(
            inner,
            args.cache,
            mode="replay" if args.llm == "replay" else args.llm,
            min_interval_s=args.min_interval if args.llm != "replay" else 0,
            normalize=normalize,
        )
        model = inner.model

    server = start_mock(args.port)
    try:
        print(f"Running {len(cases)} cases against http://127.0.0.1:{args.port}")
        results = evaluate(cases, f"http://127.0.0.1:{args.port}", provider)
    finally:
        server.should_exit = True

    md = report(results, model, args.llm)
    # No run timestamp and LF endings: an unchanged result leaves git clean.
    (HERE / "results.md").write_text(md, encoding="utf-8", newline="\n")
    (HERE / "results.json").write_text(
        json.dumps([asdict(r) for r in results], indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print()
    print(md)
    if provider is not None:
        print(f"LLM: {provider.live_calls} live calls, {provider.cache_hits} from cache")
        if args.prune:
            if any(r.llm_error for r in results):
                print("not pruning: some cases had no usable LLM answer", file=sys.stderr)
                return 1
            stale = provider.prune()
            print(f"pruned {len(stale)} unused recording(s)")
    return 0


class _ReplayOnly:
    """Stands in for Gemini during replay: any call means a cache miss."""

    name = "gemini"

    def __init__(self) -> None:
        import os

        from apidoc.llm import DEFAULT_GEMINI_MODEL

        self.model = os.environ.get("APIDOC_GEMINI_MODEL", DEFAULT_GEMINI_MODEL)

    def complete(self, system: str, prompt: str) -> str:
        raise LLMError("replay mode: no recording for this prompt")


if __name__ == "__main__":
    raise SystemExit(main())
