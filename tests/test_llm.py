import json

import httpx
import pytest

from apidoc.llm import (
    CachedProvider,
    FakeProvider,
    GeminiProvider,
    LLMError,
    LLMRateLimitError,
)


def gemini_reply(text: str, **extra) -> dict:
    return {
        "candidates": [{"content": {"parts": [{"text": text}]}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 100, "candidatesTokenCount": 20},
        **extra,
    }


def provider_with(handler) -> GeminiProvider:
    return GeminiProvider("test-key-123", "gemini-test", transport=httpx.MockTransport(handler))


def test_request_shape():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["headers"] = request.headers
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=gemini_reply('{"ok": 1}'))

    out = provider_with(handler).complete("SYSTEM", "PROMPT")
    assert out == '{"ok": 1}'
    assert seen["url"].endswith("/models/gemini-test:generateContent")
    assert "key=" not in seen["url"]  # key travels in a header, never the URL
    assert seen["headers"]["x-goog-api-key"] == "test-key-123"
    assert seen["body"]["systemInstruction"]["parts"][0]["text"] == "SYSTEM"
    assert seen["body"]["contents"][0]["parts"][0]["text"] == "PROMPT"
    assert seen["body"]["generationConfig"]["responseMimeType"] == "application/json"
    assert "thinkingConfig" not in seen["body"]["generationConfig"]


def test_thinking_level_is_opt_in():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=gemini_reply("{}"))

    p = GeminiProvider("k-12345", "m", thinking_level="low", transport=httpx.MockTransport(handler))
    p.complete("s", "p")
    assert seen["body"]["generationConfig"]["thinkingConfig"] == {"thinkingLevel": "low"}


def test_thought_parts_are_skipped():
    reply = {
        "candidates": [
            {"content": {"parts": [{"text": "thinking...", "thought": True}, {"text": "{}"}]}}
        ]
    }
    assert provider_with(lambda r: httpx.Response(200, json=reply)).complete("s", "p") == "{}"


def test_usage_is_recorded():
    p = provider_with(lambda r: httpx.Response(200, json=gemini_reply("{}")))
    p.complete("s", "p")
    assert p.last_usage["promptTokenCount"] == 100


@pytest.mark.parametrize(
    ("status", "error", "match"),
    [
        (429, LLMRateLimitError, "rate limit"),
        (400, LLMError, "GEMINI_API_KEY"),
        (403, LLMError, "GEMINI_API_KEY"),
        (404, LLMError, "APIDOC_GEMINI_MODEL"),
    ],
)
def test_error_statuses(status, error, match):
    body = {"error": {"message": "nope"}}
    with pytest.raises(error, match=match):
        provider_with(lambda r: httpx.Response(status, json=body)).complete("s", "p")


def test_retry_after_is_exposed():
    def handler(r):
        return httpx.Response(429, headers={"Retry-After": "17"}, json={})

    with pytest.raises(LLMRateLimitError) as info:
        provider_with(handler).complete("s", "p")
    assert info.value.retry_after == 17


def test_server_error_is_retried_once():
    calls = []

    def handler(r):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(503, json={"error": {"message": "busy"}})
        return httpx.Response(200, json=gemini_reply("{}"))

    import apidoc.llm as llm_module

    original = llm_module.time.sleep
    llm_module.time.sleep = lambda s: None
    try:
        assert provider_with(handler).complete("s", "p") == "{}"
    finally:
        llm_module.time.sleep = original
    assert len(calls) == 2


def test_blocked_prompt():
    reply = {"promptFeedback": {"blockReason": "SAFETY"}}
    with pytest.raises(LLMError, match="blocked"):
        provider_with(lambda r: httpx.Response(200, json=reply)).complete("s", "p")


def test_missing_key_is_a_clear_error():
    with pytest.raises(LLMError, match="GEMINI_API_KEY"):
        GeminiProvider("")


def test_record_then_replay(tmp_path):
    inner = FakeProvider(["first answer"])
    recorder = CachedProvider(inner, tmp_path, mode="record")
    assert recorder.complete("s", "p") == "first answer"
    assert recorder.live_calls == 1

    # A replay provider whose inner would fail if called: proves no API call happens.
    replayer = CachedProvider(FakeProvider([]), tmp_path, mode="replay")
    assert replayer.complete("s", "p") == "first answer"
    assert replayer.cache_hits == 1 and replayer.live_calls == 0


def test_replay_miss_is_an_error(tmp_path):
    with pytest.raises(LLMError, match="no recorded response"):
        CachedProvider(FakeProvider([]), tmp_path, mode="replay").complete("s", "p")


def test_cache_key_changes_with_prompt_and_model(tmp_path):
    a = CachedProvider(FakeProvider([], model="m1"), tmp_path)
    b = CachedProvider(FakeProvider([], model="m2"), tmp_path)
    assert a.key("s", "p") != a.key("s", "p2")
    assert a.key("s", "p") != b.key("s", "p")


def test_live_mode_never_writes(tmp_path):
    CachedProvider(FakeProvider(["x"]), tmp_path, mode="live").complete("s", "p")
    assert list(tmp_path.iterdir()) == []


def test_normalizer_makes_volatile_prompts_share_a_key(tmp_path):
    import re

    def drop_dates(text):
        return re.sub(r"date: .*", "date: <date>", text)

    c = CachedProvider(FakeProvider([]), tmp_path, normalize=drop_dates)
    assert c.key("s", "date: Mon, 05 Oct 2026") == c.key("s", "date: Tue, 06 Oct 2026")


def test_prune_deletes_only_recordings_this_run_did_not_use(tmp_path):
    stale = tmp_path / "0000stale.json"
    stale.write_text('{"response": "old"}', encoding="utf-8")
    provider = CachedProvider(FakeProvider(["fresh"]), tmp_path, mode="record")
    provider.complete("sys", "prompt")
    removed = provider.prune()
    assert removed == [stale]
    assert len(list(tmp_path.glob("*.json"))) == 1  # the recording just used
