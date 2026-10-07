"""The diagnosis pipeline: rules first, then (optionally) the LLM.

    parsed curl ─► run ─► Trace ─► rules ─► findings ─┐
                                    │                  │
                                    └── redact ────────┴─► prompt ─► LLM ─► grounding ─► merge

Guarantees this module is responsible for:
1. The LLM only ever sees redacted data. The prompt is built exclusively
   from Trace.redacted() / Finding text passed through the Redactor.
2. The LLM cannot invent evidence. Every evidence string it returns must
   appear verbatim (whitespace- and case-insensitive) in the context it was
   given. Ungrounded evidence is dropped; with none left, the LLM's answer
   is discarded.
3. Proven rule findings win. If a rule is at least STRONG_RULE confident and
   the LLM disagrees, the rule's diagnosis stands.
"""

from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from apidoc.diagnosis import Category, Diagnosis
from apidoc.llm import LLMError, Provider
from apidoc.redact import Redactor
from apidoc.rules import Context, diagnose_with_rules
from apidoc.trace import Hop

LLMMode = Literal["auto", "always", "never"]
STRONG_RULE = 0.85  # at or above this, "auto" skips the LLM and disagreements go to rules
LLM_CONFIDENCE_CAP = 0.85  # the LLM alone never claims more than a strong rule
BODY_LIMIT = 2000  # characters of each body sent to the LLM

SYSTEM_PROMPT = """You diagnose failing HTTP API calls.

You get the request as the user wrote it, every request/response hop that
actually happened, and findings from deterministic rules (which may be
incomplete or wrong when their confidence is low).

Answer with ONE JSON object, no prose around it:
{
  "category": one of %(categories)s,
  "summary": one plain-English sentence naming the cause, for a beginner,
  "evidence": 1-4 strings, each COPIED EXACTLY from the CONTEXT (a header line,
              a status line, a URL, a fragment of a body). Do not paraphrase.
  "fix": what the user should change, concretely,
  "confidence": number 0-1
}

Rules:
- Evidence must be verbatim substrings of the CONTEXT. Anything else is discarded.
- Values shown as [REDACTED] are secrets that were removed. Never guess them.
- If the context does not support a cause, use category "unknown" and say so.
"""


class LLMAnswer(BaseModel):
    category: Category
    summary: str = Field(min_length=1)
    evidence: list[str] = Field(default_factory=list)
    fix: str = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)


class LLMOutcome(BaseModel):
    """What happened on the LLM side, for -v output and the eval."""

    called: bool = False
    used: bool = False
    reason: str = ""
    answer: LLMAnswer | None = None
    dropped_evidence: list[str] = Field(default_factory=list)


def _hop_text(hop: Hop, n: int) -> str:
    req = hop.request
    lines = [f"--- hop {n} request ---", f"{req.method} {req.url}"]
    lines += [f"{k}: {v}" for k, v in req.headers]
    if req.body:
        lines.append(f"(body) {req.body[:BODY_LIMIT]}")
    lines.append(f"--- hop {n} response ---")
    lines.append(f"{hop.http_version} {hop.status} {hop.reason}")
    lines += [f"{k}: {v}" for k, v in hop.headers]
    if hop.body:
        suffix = " ...(truncated)" if len(hop.body) > BODY_LIMIT or hop.body_truncated else ""
        lines.append(f"(body) {hop.body[:BODY_LIMIT]}{suffix}")
    return "\n".join(lines)


def build_context(ctx: Context, redactor: Redactor, rule_diag: Diagnosis) -> str:
    """Everything the LLM may see, already redacted."""
    req = ctx.request.redacted(redactor)
    trace = ctx.trace.redacted(redactor)
    parts = ["=== REQUEST AS WRITTEN ===", f"{req.method} {req.url}"]
    parts += [f"{k}: {v}" for k, v in req.headers]
    if req.body:
        parts.append(f"(body) {req.body[:BODY_LIMIT]}")
    if ctx.parsed.implicit_headers:
        added = ", ".join(f"{k}: {v}" for k, v in ctx.parsed.implicit_headers)
        parts.append(f"(curl added these headers implicitly: {added})")
    parts.append(f"(follow redirects: {ctx.parsed.follow_redirects})")

    parts.append("=== WHAT HAPPENED ===")
    if trace.error:
        parts.append(f"no response: {trace.error_kind}: {trace.error}")
    parts += [_hop_text(h, i) for i, h in enumerate(trace.hops, start=1)]

    parts.append("=== RULE FINDINGS ===")
    redacted_diag = rule_diag.redacted(redactor)
    if not redacted_diag.findings:
        parts.append("(no rule matched)")
    for f in redacted_diag.findings:
        parts.append(f"- [{f.category}] confidence {f.confidence:.2f}: {f.summary}")
        parts += [f"    evidence: {e}" for e in f.evidence]
    return "\n".join(parts)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def ground(evidence: list[str], context: str) -> tuple[list[str], list[str]]:
    """Split evidence into (verbatim in context, not in context)."""
    haystack = _norm(context)
    kept, dropped = [], []
    for item in evidence:
        needle = _norm(item.strip().strip("\"'`"))
        (kept if needle and needle in haystack else dropped).append(item)
    return kept, dropped


_LABEL = re.compile(
    r"^(?:hop \d+ )?(?:response(?: body)?|status)\s*:\s*"  # rules: "response: 400 ..."
    r"|^http/\d(?:\.\d)?\s+",  # raw status line: "HTTP/1.1 400 ..."
    re.I,
)


def _evidence_key(item: str) -> str:
    """What an evidence line says, ignoring how it is written: the rules write
    'response: 400 Bad Request', the LLM copies 'HTTP/1.1 400 Bad Request'."""
    key = re.sub(r"[^a-z0-9]", "", _LABEL.sub("", item.strip()).lower())
    return key or _norm(item)  # e.g. "response body: {}": keep it, keyed as written


def merge_evidence(*groups: list[str]) -> list[str]:
    """Concatenate, dropping items that repeat an earlier one. First wording wins."""
    seen: set[str] = set()
    merged: list[str] = []
    for item in (i for g in groups for i in g):
        key = _evidence_key(item)
        if key not in seen:
            seen.add(key)
            merged.append(item)
    return merged


def _parse_answer(text: str) -> LLMAnswer:
    text = text.strip()
    if text.startswith("```"):  # tolerate ```json fences
        text = re.sub(r"^```[a-z]*\s*|\s*```$", "", text)
    return LLMAnswer.model_validate(json.loads(text))


def diagnose(
    ctx: Context,
    redactor: Redactor,
    provider: Provider | None = None,
    mode: LLMMode = "auto",
) -> tuple[Diagnosis, LLMOutcome]:
    """Return a redacted Diagnosis and a record of what the LLM did."""
    rule_diag = diagnose_with_rules(ctx)
    outcome = LLMOutcome()

    if provider is None or mode == "never":
        outcome.reason = "LLM disabled"
        return rule_diag.redacted(redactor), outcome
    if mode == "auto" and rule_diag.confidence >= STRONG_RULE:
        outcome.reason = f"rules confident ({rule_diag.confidence:.2f}); LLM not needed"
        return rule_diag.redacted(redactor), outcome

    context = build_context(ctx, redactor, rule_diag)
    prompt = f"CONTEXT:\n{context}"
    system = SYSTEM_PROMPT % {"categories": ", ".join(c.value for c in Category)}

    answer: LLMAnswer | None = None
    for attempt in range(2):
        try:
            outcome.called = True
            raw = provider.complete(system, prompt)
            answer = _parse_answer(raw)
            break
        except (ValueError, ValidationError) as exc:
            if attempt == 1:
                outcome.reason = f"LLM returned invalid JSON twice: {str(exc)[:120]}"
                return rule_diag.redacted(redactor), outcome
            prompt += (
                f"\n\nYour previous answer was invalid ({str(exc)[:200]}). "
                "Reply with only the JSON object."
            )
        except LLMError as exc:
            outcome.reason = f"LLM unavailable: {exc}"
            return rule_diag.redacted(redactor), outcome

    assert answer is not None
    # Defence in depth: the model must not echo anything secret-looking either.
    answer = answer.model_copy(
        update={
            "summary": redactor.text(answer.summary),
            "fix": redactor.text(answer.fix),
            "evidence": [redactor.text(e) for e in answer.evidence],
        }
    )
    kept, dropped = ground(answer.evidence, context)
    outcome.answer = answer
    outcome.dropped_evidence = dropped

    if not kept:
        outcome.reason = "LLM answer discarded: none of its evidence appears in the trace"
        return rule_diag.redacted(redactor), outcome

    agrees = answer.category == rule_diag.category
    # Only an actual rule *finding* can overrule the LLM. The fallback verdicts
    # ("ok", "unknown") mean no rule matched, which proves nothing.
    proven = bool(rule_diag.findings) and rule_diag.confidence >= STRONG_RULE
    if not agrees and proven:
        outcome.reason = (
            f"LLM said {answer.category}, but rule finding {rule_diag.category} is "
            f"proven ({rule_diag.confidence:.2f}); kept the rule"
        )
        return rule_diag.redacted(redactor), outcome

    outcome.used = True
    if agrees:
        outcome.reason = "LLM agreed with the rules and rewrote the explanation"
        merged = rule_diag.model_copy(
            update={
                "summary": answer.summary,
                "fix": answer.fix,
                "evidence": merge_evidence(rule_diag.evidence, kept),
                "confidence": max(rule_diag.confidence, min(answer.confidence, LLM_CONFIDENCE_CAP)),
                "source": "rules+llm",
            }
        )
        return merged.redacted(redactor), outcome

    outcome.reason = "rules were unsure; used the LLM's grounded diagnosis"
    llm_diag = Diagnosis(
        category=answer.category,
        summary=answer.summary,
        evidence=kept,
        fix=answer.fix,
        confidence=min(answer.confidence, LLM_CONFIDENCE_CAP),
        source="llm",
        fixed_request=None,  # the LLM never rewrites requests; only rules do
        findings=rule_diag.findings,
    )
    return llm_diag.redacted(redactor), outcome
