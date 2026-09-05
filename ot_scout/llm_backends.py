"""Chat backends for the assessment copilot.

Every backend takes a system prompt and a user prompt and returns the model's text. Three
real backends, all standard-library only (urllib), so the project stays dependency-free:

  ollama     Ollama's native API (default http://127.0.0.1:11434). Local, offline.
  openai     Any OpenAI-compatible /v1/chat/completions server: OpenAI itself, a llama.cpp
             server (`llama-server --port 8080`), LM Studio, vLLM. Local or cloud.
  anthropic  Anthropic Messages API. Cloud.

The copilot never depends on which backend answered. The same prompt goes to a 7B model on
the assessment box and to a frontier model during prompt development; only the log differs.
Nothing in this module reads the assessment database.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Iterator

StreamCallback = Callable[[str], None]


class BackendError(RuntimeError):
    """The backend could not be reached or returned an unusable reply."""


@dataclass
class ChatResult:
    text: str
    model: str
    backend: str
    latency_seconds: float
    first_token_seconds: float | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    raw: dict = field(default_factory=dict, repr=False)


class Backend:
    name = "base"

    def __init__(self, model: str, url: str, api_key: str = "", timeout: int = 1800, json_mode: bool = True,
                 temperature: float = 0.1, max_tokens: int = 1500):
        self.model = model
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.json_mode = json_mode
        self.temperature = temperature
        self.max_tokens = max_tokens

    def chat(self, system: str, user: str, on_token: StreamCallback | None = None) -> ChatResult:
        raise NotImplementedError

    def describe(self) -> str:
        return f"{self.name}:{self.model} @ {self.url}"

    # -- helpers -------------------------------------------------------------------------
    def _request(self, path: str, payload: dict, headers: dict | None = None) -> urllib.request.Request:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.url + path, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        return req

    def _open(self, req: urllib.request.Request):
        try:
            return urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise BackendError(f"{self.describe()} returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise BackendError(f"Cannot reach {self.describe()}: {exc.reason}") from exc

    @staticmethod
    def _lines(response) -> Iterator[str]:
        for raw in response:
            line = raw.decode("utf-8", "replace").strip()
            if line:
                yield line


class OllamaBackend(Backend):
    name = "ollama"

    def __init__(self, model: str = "qwen2.5:7b", url: str = "http://127.0.0.1:11434", **kw):
        super().__init__(model, url, **kw)

    def chat(self, system: str, user: str, on_token: StreamCallback | None = None) -> ChatResult:
        payload = {"model": self.model, "stream": True,
                   "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                   "options": {"temperature": self.temperature, "num_predict": self.max_tokens, "num_ctx": 16384}}
        if self.json_mode:
            payload["format"] = "json"
        started = time.monotonic()
        first = None
        parts: list[str] = []
        final: dict = {}
        with self._open(self._request("/api/chat", payload)) as resp:
            for line in self._lines(resp):
                chunk = json.loads(line)
                token = (chunk.get("message") or {}).get("content", "")
                if token:
                    if first is None:
                        first = time.monotonic() - started
                    parts.append(token)
                    if on_token:
                        on_token(token)
                if chunk.get("done"):
                    final = chunk
        return ChatResult("".join(parts), final.get("model", self.model), self.name, time.monotonic() - started, first,
                          final.get("prompt_eval_count"), final.get("eval_count"), final)


class OpenAICompatibleBackend(Backend):
    """OpenAI, llama.cpp server, LM Studio, vLLM — anything speaking /v1/chat/completions."""
    name = "openai"

    def __init__(self, model: str = "gpt-4o-mini", url: str = "https://api.openai.com", api_key: str = "", **kw):
        super().__init__(model, url, api_key or os.environ.get("OPENAI_API_KEY", ""), **kw)

    def chat(self, system: str, user: str, on_token: StreamCallback | None = None) -> ChatResult:
        payload = {"model": self.model, "stream": True, "temperature": self.temperature, "max_tokens": self.max_tokens,
                   "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                   "stream_options": {"include_usage": True}}
        if self.json_mode:
            payload["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        started = time.monotonic()
        first = None
        parts: list[str] = []
        usage: dict = {}
        model = self.model
        with self._open(self._request("/v1/chat/completions", payload, headers)) as resp:
            for line in self._lines(resp):
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                chunk = json.loads(data)
                model = chunk.get("model") or model
                if chunk.get("usage"):
                    usage = chunk["usage"]
                for choice in chunk.get("choices") or []:
                    token = (choice.get("delta") or {}).get("content") or ""
                    if token:
                        if first is None:
                            first = time.monotonic() - started
                        parts.append(token)
                        if on_token:
                            on_token(token)
        return ChatResult("".join(parts), model, self.name, time.monotonic() - started, first,
                          usage.get("prompt_tokens"), usage.get("completion_tokens"), {"usage": usage})


class LlamaCppBackend(OpenAICompatibleBackend):
    """llama.cpp's `llama-server` — OpenAI-compatible, defaults to localhost:8080, no key."""
    name = "llamacpp"

    def __init__(self, model: str = "local", url: str = "http://127.0.0.1:8080", api_key: str = "", **kw):
        Backend.__init__(self, model, url, api_key, **kw)


class AnthropicBackend(Backend):
    name = "anthropic"

    def __init__(self, model: str = "claude-sonnet-4-5", url: str = "https://api.anthropic.com", api_key: str = "", **kw):
        super().__init__(model, url, api_key or os.environ.get("ANTHROPIC_API_KEY", ""), **kw)

    def chat(self, system: str, user: str, on_token: StreamCallback | None = None) -> ChatResult:
        if not self.api_key:
            raise BackendError("ANTHROPIC_API_KEY is not set")
        # Anthropic has no JSON mode switch; the prompt asks for JSON and the validator checks it.
        payload = {"model": self.model, "stream": True, "max_tokens": self.max_tokens, "temperature": self.temperature,
                   "system": system, "messages": [{"role": "user", "content": user}]}
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}
        started = time.monotonic()
        first = None
        parts: list[str] = []
        usage: dict = {}
        model = self.model
        with self._open(self._request("/v1/messages", payload, headers)) as resp:
            for line in self._lines(resp):
                if not line.startswith("data:"):
                    continue
                event = json.loads(line[5:].strip())
                kind = event.get("type")
                if kind == "message_start":
                    model = event.get("message", {}).get("model", model)
                    usage.update(event.get("message", {}).get("usage") or {})
                elif kind == "content_block_delta":
                    token = (event.get("delta") or {}).get("text") or ""
                    if token:
                        if first is None:
                            first = time.monotonic() - started
                        parts.append(token)
                        if on_token:
                            on_token(token)
                elif kind == "message_delta":
                    usage.update(event.get("usage") or {})
        return ChatResult("".join(parts), model, self.name, time.monotonic() - started, first,
                          usage.get("input_tokens"), usage.get("output_tokens"), {"usage": usage})


class ScriptedBackend(Backend):
    """Returns canned replies. For tests, `--dry-run` and prompt work with no model running."""
    name = "scripted"

    def __init__(self, replies: list[str] | None = None, model: str = "scripted"):
        super().__init__(model, "memory://")
        self.replies = list(replies or [])
        self.calls: list[tuple[str, str]] = []

    def describe(self) -> str:
        return "no model (dry run)"

    def chat(self, system: str, user: str, on_token: StreamCallback | None = None) -> ChatResult:
        self.calls.append((system, user))
        text = self.replies.pop(0) if self.replies else "{}"
        if on_token:
            on_token(text)
        return ChatResult(text, self.model, self.name, 0.0, 0.0, len(system + user) // 4, len(text) // 4)


BACKENDS = {"ollama": OllamaBackend, "openai": OpenAICompatibleBackend, "llamacpp": LlamaCppBackend,
            "anthropic": AnthropicBackend}

DEFAULT_MODELS = {"ollama": "qwen2.5:7b", "openai": "gpt-4o-mini", "llamacpp": "local", "anthropic": "claude-sonnet-4-5"}


def make_backend(name: str, model: str | None = None, url: str | None = None, api_key: str = "", **kw) -> Backend:
    try:
        cls = BACKENDS[name]
    except KeyError:
        raise BackendError(f"Unknown backend '{name}' (choose from {', '.join(BACKENDS)})") from None
    args: dict = {}
    if model:
        args["model"] = model
    if url:
        args["url"] = url
    if api_key or name in ("openai", "anthropic"):
        args["api_key"] = api_key
    return cls(**args, **kw)
