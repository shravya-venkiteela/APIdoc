from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Literal, Protocol

import httpx

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"


class LLMError(RuntimeError):
    pass


class LLMRateLimitError(LLMError):
    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class Provider(Protocol):
    name: str
    model: str

    def complete(self, system: str, prompt: str) -> str: ...


class GeminiProvider:
    name = "gemini"

    def __init__(
        self,
        api_key: str,
        model: str | None = None,
        *,
        thinking_level: str | None = None,
        max_output_tokens: int = 2048,
        timeout: float = 60.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not api_key:
            raise LLMError("no Gemini API key: set GEMINI_API_KEY or use --no-llm")
        self.api_key = api_key
        self.model = model or os.environ.get("APIDOC_GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
        self.thinking_level = thinking_level or os.environ.get("APIDOC_GEMINI_THINKING")
        self.max_output_tokens = max_output_tokens
        self._client = httpx.Client(timeout=timeout, transport=transport)
        self.last_usage: dict = {}

    @classmethod
    def from_env(cls) -> GeminiProvider:
        return cls(os.environ.get("GEMINI_API_KEY", ""))

    def complete(self, system: str, prompt: str) -> str:
        config: dict = {
            "responseMimeType": "application/json",
            "maxOutputTokens": self.max_output_tokens,
        }
        if self.thinking_level:
            config["thinkingConfig"] = {"thinkingLevel": self.thinking_level}
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": config,
        }
        url = GEMINI_URL.format(model=self.model)
        #The key goes in a header, never the URL: URLs end up in logs.
        headers = {"x-goog-api-key": self.api_key, "Content-Type": "application/json"}

        for attempt in range(2):
            try:
                response = self._client.post(url, json=body, headers=headers)
            except httpx.HTTPError as exc:
                raise LLMError(f"could not reach Gemini: {type(exc).__name__}") from exc
            if response.status_code >= 500 and attempt == 0:
                time.sleep(2)
                continue
            break
        return self._parse(response)

    def _parse(self, response: httpx.Response) -> str:
        if response.status_code == 429:
            retry = response.headers.get("retry-after")
            raise LLMRateLimitError(
                "Gemini rate limit hit (free tier is per-minute and per-day). Wait, or "
                "lower the eval rate.",
                retry_after=float(retry) if retry and retry.isdigit() else None,
            )
        if response.status_code in (400, 401, 403):
            raise LLMError(
                f"Gemini rejected the request ({response.status_code}): "
                f"{_error_message(response)}. Check GEMINI_API_KEY."
            )
        if response.status_code == 404:
            raise LLMError(
                f"Gemini model {self.model!r} unavailable: {_error_message(response)}. "
                "Set APIDOC_GEMINI_MODEL to another model from the models list."
            )
        if response.status_code >= 400:
            raise LLMError(f"Gemini error {response.status_code}: {_error_message(response)}")

        data = response.json()
        self.last_usage = data.get("usageMetadata", {})
        if block := data.get("promptFeedback", {}).get("blockReason"):
            raise LLMError(f"Gemini blocked the prompt: {block}")
        candidates = data.get("candidates") or []
        if not candidates:
            raise LLMError("Gemini returned no candidates")
        parts = candidates[0].get("content", {}).get("parts", [])
        # Skip thought summaries if a thinking model includes them.
        text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
        if not text:
            reason = candidates[0].get("finishReason", "unknown")
            raise LLMError(f"Gemini returned no text (finishReason={reason})")
        return text


def _error_message(response: httpx.Response) -> str:
    try:
        return response.json()["error"]["message"]
    except (ValueError, KeyError, TypeError):
        return response.text[:200]


class FakeProvider:
    """Returns canned responses and records every prompt it was sent.

    Tests use `prompts` to prove what would have left the machine.
    """

    name = "fake"

    def __init__(
        self,
        responses: Iterable[str] | Callable[[str, str], str],
        model: str = "fake-1",
    ) -> None:
        self.model = model
        self._fn = responses if callable(responses) else None
        self._queue = None if callable(responses) else list(responses)
        self.prompts: list[tuple[str, str]] = []

    def complete(self, system: str, prompt: str) -> str:
        self.prompts.append((system, prompt))
        if self._fn is not None:
            return self._fn(system, prompt)
        if not self._queue:
            raise LLMError("FakeProvider ran out of responses")
        return self._queue.pop(0)


# ------------------------------------------------------------------ cache ---

CacheMode = Literal["live", "record", "replay"]


class CachedProvider:
    """Record/replay wrapper.

    live    always call the provider, never touch the cache
    record  return cached responses when present, otherwise call and save
    replay  only use the cache; a miss is an error (this is what CI runs)

    Keys hash the provider, model and full prompt, so changing the prompt or
    the model invalidates old recordings automatically.
    """

    def __init__(
        self,
        inner: Provider,
        cache_dir: Path,
        mode: CacheMode = "record",
        min_interval_s: float = 0.0,
    ) -> None:
        self.inner = inner
        self.name = inner.name
        self.model = inner.model
        self.cache_dir = Path(cache_dir)
        self.mode = mode
        self.min_interval_s = min_interval_s
        self._last_call = 0.0
        self.live_calls = 0
        self.cache_hits = 0

    def key(self, system: str, prompt: str) -> str:
        raw = json.dumps([self.name, self.model, system, prompt]).encode()
        return hashlib.sha256(raw).hexdigest()[:32]

    def complete(self, system: str, prompt: str) -> str:
        path = self.cache_dir / f"{self.key(system, prompt)}.json"
        if self.mode != "live" and path.exists():
            self.cache_hits += 1
            return json.loads(path.read_text(encoding="utf-8"))["response"]
        if self.mode == "replay":
            raise LLMError(f"no recorded response for this prompt ({path.name}); run with record")
        self._throttle()
        text = self.inner.complete(system, prompt)
        self.live_calls += 1
        if self.mode == "record":
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            record = {"provider": self.name, "model": self.model, "response": text}
            path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        return text

    def _throttle(self) -> None:
        """Stay under free-tier per-minute limits during an eval run."""
        wait = self.min_interval_s - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()


if __name__ == "__main__":
    # Smoke test with your real key:  python -m apidoc.llm
    provider = GeminiProvider.from_env()
    print(f"model: {provider.model}")
    reply = provider.complete(
        "Reply with JSON only.", 'Return {"ok": true, "model_says": "<one short sentence>"}'
    )
    print(f"reply: {reply}")
    print(f"usage: {provider.last_usage}")
