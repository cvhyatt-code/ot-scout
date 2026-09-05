"""Copilot behind the web UI: settings, one-question-at-a-time execution, session history.

The CLI (copilot.py) and this service share everything that matters — Evidence selection, the prompt,
the grounding check and the JSONL log — so an answer in the app and an answer at the terminal are the
same answer. What this adds is a place to keep the model connection (backend, model, URL, key) and a
short in-memory history for the panel.

Settings live in data/copilot-settings.json next to the databases, mode 0600, never inside an
assessment database: the evidence package must never carry an API key. The key is never returned to
the browser, only whether one is set and its last four characters.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from .copilot import DEFAULT_BUDGET, STANDARD_QUESTIONS, Copilot
from .llm_backends import BACKENDS, DEFAULT_MODELS, Backend, BackendError, make_backend

DEFAULTS = {"backend": "anthropic", "model": "", "url": "", "api_key": "", "max_tokens": 3000,
            "budget": DEFAULT_BUDGET, "timeout": 600}
ENV_KEYS = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}
HISTORY = 20


class CopilotService:
    def __init__(self, settings_path: str | Path, log_path: str | Path | None = None, backend_factory=make_backend):
        self.settings_path = Path(settings_path)
        self.log_path = Path(log_path) if log_path else self.settings_path.parent / "copilot-log.jsonl"
        self._factory = backend_factory
        self._lock = threading.Lock()
        self.busy_question: str | None = None
        self.busy_since: float | None = None
        self.history: list[dict] = []
        self.settings = dict(DEFAULTS)
        self._load()

    # -- settings --------------------------------------------------------------------------
    def _load(self):
        if self.settings_path.is_file():
            try:
                stored = json.loads(self.settings_path.read_text(encoding="utf-8"))
                self.settings.update({k: stored[k] for k in DEFAULTS if k in stored})
            except (OSError, ValueError):
                pass

    def save(self, changes: dict) -> dict:
        new = dict(self.settings)
        for key in ("backend", "model", "url"):
            if key in changes:
                new[key] = str(changes[key] or "").strip()
        if new["backend"] not in BACKENDS:
            raise ValueError(f"Unknown backend '{new['backend']}'")
        for key, lo, hi in (("max_tokens", 200, 32000), ("budget", 1000, 200000), ("timeout", 30, 7200)):
            if key in changes and str(changes[key]).strip():
                try:
                    value = int(changes[key])
                except (TypeError, ValueError):
                    raise ValueError(f"{key} must be a whole number") from None
                if not lo <= value <= hi:
                    raise ValueError(f"{key} must be between {lo} and {hi}")
                new[key] = value
        # an empty key field means "keep what is saved"; the explicit clear flag removes it
        if changes.get("clear_api_key"):
            new["api_key"] = ""
        elif str(changes.get("api_key") or "").strip():
            new["api_key"] = str(changes["api_key"]).strip()
        self.settings = new
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.settings_path.write_text(json.dumps(new, indent=2), encoding="utf-8")
        try:
            os.chmod(self.settings_path, 0o600)
        except OSError:
            pass
        return self.public()

    def effective_key(self) -> str:
        return self.settings["api_key"] or os.environ.get(ENV_KEYS.get(self.settings["backend"], ""), "")

    def public(self) -> dict:
        """Settings as the browser may see them — the key itself never leaves the box."""
        key = self.effective_key()
        s = self.settings
        return {"backend": s["backend"], "model": s["model"] or DEFAULT_MODELS[s["backend"]], "model_is_default": not s["model"],
                "url": s["url"], "max_tokens": s["max_tokens"], "budget": s["budget"], "timeout": s["timeout"],
                "api_key_set": bool(key), "api_key_hint": ("…" + key[-4:]) if key else "",
                "api_key_source": "saved" if s["api_key"] else ("environment" if key else "none"),
                "local": s["backend"] in ("ollama", "llamacpp") or (s["url"].startswith("http://127.") or s["url"].startswith("http://localhost"))}

    def status(self) -> dict:
        return {"settings": self.public(), "backends": sorted(BACKENDS), "default_models": DEFAULT_MODELS,
                "standard_questions": STANDARD_QUESTIONS, "history": self.history,
                "busy": self.busy_question, "busy_seconds": round(time.monotonic() - self.busy_since, 1) if self.busy_since else None,
                "log": str(self.log_path)}

    # -- model calls -----------------------------------------------------------------------
    def _backend(self, **overrides) -> Backend:
        s = self.settings
        kw = {"json_mode": True, "max_tokens": s["max_tokens"], "timeout": s["timeout"]}
        kw.update(overrides)
        return self._factory(s["backend"], s["model"] or None, s["url"] or None, self.effective_key(), **kw)

    def ask(self, export: dict, question: str) -> dict:
        question = (question or "").strip()
        if not question:
            raise ValueError("Ask a question")
        if len(question) > 2000:
            raise ValueError("Keep the question under 2,000 characters")
        if not self._lock.acquire(blocking=False):
            raise RuntimeError(f"Still working on: {self.busy_question}")
        try:
            self.busy_question, self.busy_since = question, time.monotonic()
            copilot = Copilot(export, self._backend(), self.log_path, self.settings["budget"])
            try:
                answer = copilot.ask(question)
            except BackendError as exc:
                raise RuntimeError(str(exc)) from exc
            row = answer.to_log()
            row["check"] = answer.validation.summary()
            row["grounded"] = answer.validation.grounded
            row["dataset"] = copilot.evidence.context.get("assessment") or ""
            # names for the ASSET- ids the model cited, so the finding hand-off can name assets the way the register does
            row["asset_names"] = {rid: rec.data.get("name") or rec.data.get("ips") or rec.data.get("mac") or rid
                                  for rid, rec in copilot.evidence.records.items()
                                  if rec.kind == "asset" and rid in (answer.reply or {}).get("evidence_ids", [])}
            self.history.insert(0, row)
            del self.history[HISTORY:]
            return row
        finally:
            self.busy_question, self.busy_since = None, None
            self._lock.release()

    def test(self) -> dict:
        """A tiny round trip that proves the connection, key and model name — costs a few tokens."""
        backend = self._backend(max_tokens=40, json_mode=False, timeout=min(120, self.settings["timeout"]))
        started = time.monotonic()
        try:
            result = backend.chat("Reply with exactly the word: ready", "Are you ready?")
        except BackendError as exc:
            raise RuntimeError(str(exc)) from exc
        return {"ok": True, "backend": backend.describe(), "model": result.model, "reply": result.text.strip()[:80],
                "seconds": round(time.monotonic() - started, 2)}
