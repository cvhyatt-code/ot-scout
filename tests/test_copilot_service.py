import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ot_scout.copilot_service import CopilotService  # noqa: E402
from ot_scout.llm_backends import ScriptedBackend  # noqa: E402

def good_reply(question="What should I look at first?"):
    """A well-behaved answer: cites only ids that the selector actually sends for this question."""
    from ot_scout.copilot import Evidence
    ids = [r.id for r in Evidence(EXPORT).select(question)][:3]
    return json.dumps({"observed_facts": [f"{ids[0]} and {ids[1]} were observed"], "analysis": "Routine so far.",
                       "potential_concerns": [f"Unreviewed path ({ids[0]})"], "alternative_explanations": ["Historian collection"],
                       "recommended_validation": ["Ask the controls engineer"], "evidence_ids": ids[:2],
                       "confidence": "medium", "insufficient_evidence": []})


def _export():
    """The real export shape, from the fictitious demo data set (built if missing)."""
    import importlib
    from ot_scout.copilot import export_from_database
    path = Path(__file__).resolve().parent.parent / "data" / "demo.db"
    if not path.exists():
        importlib.import_module("demo").build_demo(path)
    return export_from_database(path)


EXPORT = _export()
GOOD = good_reply()



def scripted_factory(replies):
    def factory(name, model=None, url=None, api_key="", **kw):
        b = ScriptedBackend(list(replies), model=model or "scripted")
        b.name = name
        b.kw = kw
        return b
    return factory


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "copilot-settings.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_defaults_and_public_view_hide_the_key(self):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        svc = CopilotService(self.path)
        pub = svc.public()
        self.assertEqual(pub["backend"], "anthropic")
        self.assertFalse(pub["api_key_set"])
        self.assertEqual(pub["api_key_source"], "none")
        self.assertEqual(pub["max_tokens"], 3000)
        svc.save({"api_key": "sk-test-ABCD1234"})
        pub = svc.public()
        self.assertTrue(pub["api_key_set"])
        self.assertEqual(pub["api_key_hint"], "…1234")
        self.assertNotIn("sk-test", json.dumps(pub))
        self.assertNotIn("sk-test", json.dumps(svc.status()))
        # persisted, private, and an empty key field keeps the saved one
        self.assertEqual(json.loads(self.path.read_text())["api_key"], "sk-test-ABCD1234")
        if os.name == "posix":
            self.assertEqual(oct(self.path.stat().st_mode & 0o777), "0o600")
        svc.save({"api_key": "", "model": "claude-sonnet-4-5"})
        self.assertEqual(svc.settings["api_key"], "sk-test-ABCD1234")
        svc.save({"clear_api_key": True})
        self.assertEqual(svc.settings["api_key"], "")

    def test_settings_validation(self):
        svc = CopilotService(self.path)
        with self.assertRaises(ValueError):
            svc.save({"backend": "skynet"})
        with self.assertRaises(ValueError):
            svc.save({"max_tokens": "lots"})
        with self.assertRaises(ValueError):
            svc.save({"timeout": 5})
        svc.save({"backend": "ollama", "model": "qwen2.5:7b", "url": "http://127.0.0.1:11434"})
        self.assertTrue(svc.public()["local"])
        self.assertTrue(svc.public()["api_key_set"] is False)

    def test_ask_uses_saved_settings_logs_and_keeps_history(self):
        svc = CopilotService(self.path, backend_factory=scripted_factory([GOOD]))
        svc.save({"backend": "ollama", "max_tokens": 2222, "timeout": 900, "budget": 5000})
        row = svc.ask(EXPORT, "What should I look at first?")
        self.assertTrue(row["grounded"])
        self.assertIn("grounded", row["check"])
        self.assertEqual(row["dataset"], EXPORT["sessions"][0]["assessment"])
        self.assertEqual(row["reply"]["confidence"], "medium")
        self.assertEqual(svc.history[0]["question"], "What should I look at first?")
        log = (Path(self.tmp.name) / "copilot-log.jsonl").read_text().splitlines()
        self.assertEqual(len(log), 1)
        self.assertEqual(json.loads(log[0])["backend"], "ollama")

    def test_ask_flags_invented_evidence(self):
        bad = json.dumps({"observed_facts": ["REL-099 shows 10.9.9.9 talking to ASSET-001"], "analysis": "", "potential_concerns": [],
                          "alternative_explanations": [], "recommended_validation": [], "evidence_ids": ["REL-099"], "confidence": "high", "insufficient_evidence": []})
        svc = CopilotService(self.path, backend_factory=scripted_factory([bad]))
        row = svc.ask(EXPORT, "Anything odd?")
        self.assertFalse(row["grounded"])
        self.assertIn("REL-099", row["check"])
        self.assertIn("10.9.9.9", row["check"])

    def test_one_question_at_a_time(self):
        gate = threading.Event()

        class Slow(ScriptedBackend):
            def chat(self, system, user, on_token=None):
                gate.wait(5)
                return super().chat(system, user, on_token)

        def factory(name, model=None, url=None, api_key="", **kw):
            return Slow([GOOD])

        svc = CopilotService(self.path, backend_factory=factory)
        results = {}
        t = threading.Thread(target=lambda: results.setdefault("first", svc.ask(EXPORT, "What should I look at first?")))
        t.start()
        for _ in range(100):
            if svc.busy_question:
                break
            threading.Event().wait(0.01)
        with self.assertRaises(RuntimeError) as ctx:
            svc.ask(EXPORT, "second")
        self.assertIn("What should I look at first?", str(ctx.exception))
        gate.set(); t.join(5)
        self.assertTrue(results["first"]["grounded"])
        self.assertIsNone(svc.busy_question)

    def test_empty_question_rejected(self):
        svc = CopilotService(self.path, backend_factory=scripted_factory([GOOD]))
        with self.assertRaises(ValueError):
            svc.ask(EXPORT, "   ")


class WebTests(unittest.TestCase):
    """The three routes, through the real handler, against a scripted backend."""

    @classmethod
    def setUpClass(cls):
        from ot_scout.capture import CaptureManager
        from ot_scout.store import Store
        from ot_scout.web import AppServer, Handler
        cls.tmp = tempfile.TemporaryDirectory()
        store = Store(str(Path(cls.tmp.name) / "t.db"))
        cls.server = AppServer(("127.0.0.1", 0), Handler, store, CaptureManager(store))
        cls.server.copilot._factory = scripted_factory([GOOD, GOOD, GOOD])
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.tmp.cleanup()

    def call(self, path, body=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"}, method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_status_settings_ask(self):
        status, d = self.call("/api/copilot")
        self.assertEqual(status, 200)
        self.assertIn("standard_questions", d)
        self.assertEqual(d["settings"]["backend"], "anthropic")
        status, d = self.call("/api/copilot/settings", {"backend": "ollama", "model": "qwen2.5:7b"})
        self.assertEqual(status, 200)
        self.assertEqual(d["settings"]["model"], "qwen2.5:7b")
        status, d = self.call("/api/copilot/settings", {"backend": "nope"})
        self.assertEqual(status, 400)
        status, d = self.call("/api/copilot/ask", {"question": "What should I look at first?"})
        self.assertEqual(status, 200, d)
        self.assertIn("check", d["answer"])
        status, d = self.call("/api/copilot")
        self.assertEqual(len(d["history"]), 1)
        status, d = self.call("/api/copilot/ask", {"question": ""})
        self.assertEqual(status, 400)
        status, d = self.call("/api/copilot/test", {})
        self.assertEqual(status, 200, d)
        self.assertTrue(d["ok"])


if __name__ == "__main__":
    unittest.main()
