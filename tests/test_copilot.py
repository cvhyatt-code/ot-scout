import json
import tempfile
import unittest
from pathlib import Path

from ot_scout.copilot import (STANDARD_QUESTIONS, Copilot, Evidence, build_user_prompt, parse_json_reply,
                              summarize_log, validate)
from ot_scout.llm_backends import BackendError, ScriptedBackend, make_backend


def export():
    """A tiny assessment export in the shape of Store.json_export()."""
    return {
        "generated_at": "2026-09-05T12:00:00+00:00",
        "summary": {"assets": 4, "relationships": 3, "flows": 2, "packets": 900, "sessions": 1},
        "sessions": [{"id": 1, "assessment": "Test Plant — OT assessment", "site": "Main", "collection_point": "Core SPAN",
                      "interface": "eth0", "started_at": "2026-09-01T10:00:00+00:00", "duration": "42:00", "packets": 900,
                      "dropped": 0, "source_type": "live", "access_method": "SPAN"}],
        "assets": [
            {"id": 1, "name": "PLC-01", "display_type": "PLC", "type_confidence": 95, "type_evidence": "S7comm", "type_source": "Assessor override",
             "vendor": "Siemens AG", "manufacturer": "Siemens AG", "model": "6ES7 315", "ips": "10.10.20.15", "mac": "00:1c:06:00:00:15",
             "classification": "Physical endpoint", "purdue_level": "Level 1", "purdue_source": "Assessor", "zone": "Cell A",
             "criticality": "Critical", "source": "Physical walkdown", "packets": 400, "observed_protocols": "ARP, S7COMM",
             "exposure": 62, "exposure_band": "High", "exposure_factors": ["Criticality Critical (+40)", "Talks to an external endpoint (+22)"],
             "support_status": "End of support"},
            {"id": 2, "name": "", "display_type": "Unknown device", "auto_type": "Unknown device", "type_confidence": 30,
             "type_evidence": "MAC OUI only", "type_source": "Automatic", "vendor": "Unknown", "ips": "10.10.20.99",
             "mac": "00:11:22:33:44:99", "classification": "Physical endpoint", "source": "Passive capture", "packets": 12,
             "observed_protocols": "ARP, HTTPS", "exposure": 10, "exposure_band": "Low"},
            {"id": 3, "name": "HIST-01", "display_type": "Historian", "type_confidence": 95, "type_source": "Assessor override",
             "vendor": "Dell Inc.", "ips": "172.16.5.22", "mac": "00:14:22:00:00:22", "classification": "Physical endpoint",
             "purdue_level": "Level 3", "purdue_source": "Assessor", "zone": "Site ops", "criticality": "High",
             "source": "Physical walkdown", "packets": 300, "observed_protocols": "OPC-UA", "exposure": 30, "exposure_band": "Moderate"},
            {"id": 4, "name": "Assessor laptop", "display_type": "Assessment collector (not client asset)", "type_confidence": 100,
             "type_source": "Assessor override", "vendor": "Dell Inc.", "ips": "10.10.20.200", "mac": "00:14:22:aa:00:01",
             "classification": "Physical endpoint", "source": "Physical walkdown", "packets": 5, "exposure": 0, "exposure_band": "Low"},
        ],
        "relationships": [
            {"endpoint_a": "PLC-01", "endpoint_b": "HIST-01", "protocols": "OPC-UA", "key_a": "asset:1", "key_b": "asset:3",
             "level_a": "Level 1", "level_b": "Level 3", "crossing": "Level 1 to Level 3", "decision": "Approved",
             "purpose": "Historian collection", "category": "Local asset-to-asset", "flows": 2, "packets": 500, "external_ips": 0},
            {"endpoint_a": "PLC-01", "endpoint_b": "203.0.113.7", "protocols": "HTTPS", "key_a": "asset:1", "key_b": "ip:203.0.113.7",
             "level_a": "Level 1", "level_b": "External", "crossing": "OT to external/internet", "decision": "",
             "purpose": "", "category": "Asset-to-external/unknown", "flows": 1, "packets": 140, "external_ips": 1},
            {"endpoint_a": "10.10.20.99", "endpoint_b": "PLC-01", "protocols": "HTTPS", "key_a": "asset:2", "key_b": "asset:1",
             "level_a": "", "level_b": "Level 1", "crossing": "", "decision": "Unexpected", "purpose": "", "category": "Local asset-to-asset",
             "flows": 1, "packets": 20, "external_ips": 0},
        ],
        "flows": [
            {"id": 7, "session_id": 1, "src_ip": "10.10.20.15", "dst_ip": "203.0.113.7", "transport": "TCP", "src_port": 51000, "dst_port": 443,
             "app_protocol": "HTTPS", "traffic_scope": "Unicast", "packets": 140, "collection_point": "Core SPAN", "src_name": "PLC-01", "dst_name": ""},
            {"id": 8, "session_id": 1, "src_ip": "10.10.20.15", "dst_ip": "172.16.5.22", "transport": "TCP", "src_port": 51001, "dst_port": 4840,
             "app_protocol": "OPC-UA", "traffic_scope": "Unicast", "packets": 500, "collection_point": "Core SPAN", "src_name": "PLC-01", "dst_name": "HIST-01"},
        ],
        "discovery_traffic": [],
        "sites": [{"id": 1, "assessment": "Test Plant — OT assessment", "name": "Main", "facility_type": "Water treatment",
                   "deviations": "Unlabelled device in panel 3",
                   "checklist": [{"item": "ingress_egress", "label": "Network ingress and egress points", "status": "Not started"}]}],
        "findings": [{"id": 1, "ref": "FND-01", "title": "PLC talks to the internet", "kind": "Control deficiency", "rating": "High priority",
                      "confidence": "Medium", "condition": "PLC-01 opened HTTPS to a public address", "evidence": "140 packets to 203.0.113.7:443",
                      "recommendation": "Confirm the destination and block if unapproved"}],
        "zones": {"levels": {"Level 1": {"assets": 1}, "Level 3": {"assets": 1}, "Unassigned": {"assets": 2}}, "assigned": 2, "physical": 4},
    }


GOOD_REPLY = json.dumps({
    "observed_facts": ["PLC-01 (ASSET-001) at 10.10.20.15 sent HTTPS to 203.0.113.7 (REL-002, FLOW-007)."],
    "analysis": "A Level 1 controller reaching a public address warrants validation.",
    "potential_concerns": ["Unreviewed external path from a control asset (REL-002)."],
    "alternative_explanations": ["Vendor telemetry or time service."],
    "recommended_validation": ["Identify the owner of 203.0.113.7."],
    "evidence_ids": ["ASSET-001", "REL-002", "FLOW-007"],
    "confidence": "medium",
    "insufficient_evidence": ["Firewall policy for the path."],
})

BAD_REPLY = json.dumps({
    "observed_facts": ["PLC-01 (ASSET-001) also talks to 192.168.77.5 over Modbus (REL-042)."],
    "analysis": "x", "potential_concerns": [], "alternative_explanations": [], "recommended_validation": [],
    "evidence_ids": ["ASSET-001", "REL-042"], "confidence": "high", "insufficient_evidence": [],
})


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.ev = Evidence(export())

    def test_stable_identifiers_and_tags(self):
        self.assertIn("ASSET-001", self.ev.records)
        self.assertIn("REL-001", self.ev.records)
        self.assertIn("FLOW-007", self.ev.records)
        self.assertIn("CAP-001", self.ev.records)
        self.assertIn("SITE-001", self.ev.records)
        self.assertIn("FND-01", self.ev.records)
        unknown = self.ev.records["ASSET-002"]
        self.assertIn("undocumented", unknown.tags)
        self.assertIn("low_confidence_type", unknown.tags)
        self.assertFalse(unknown.data["documented"])
        self.assertIn("collector", self.ev.records["ASSET-004"].tags)
        # relationship ids are assigned in a deterministic order (by key_a, key_b, protocols)
        rels = [r for r in self.ev.records.values() if r.kind == "relationship"]
        external = next(r for r in rels if r.data["boundary_crossing"] == "OT to external/internet")
        self.assertEqual(external.data["conduit_decision"], "Unknown")  # empty decision reads as not yet reviewed
        self.assertIn("external", external.tags)
        self.assertIn("unreviewed", external.tags)
        self.assertEqual(self.ev.stats()["undocumented_assets"], 1)
        self.assertEqual(self.ev.stats()["external_relationships"], 1)

    def test_selection_prioritises_the_interesting_records_and_excludes_the_collector(self):
        chosen = self.ev.select(STANDARD_QUESTIONS[0])
        ids = [r.id for r in chosen]
        self.assertNotIn("ASSET-004", ids)
        external = next(r.id for r in chosen if r.kind == "relationship" and "external" in r.tags)
        unexpected = next(r.id for r in chosen if r.kind == "relationship" and "unexpected" in r.tags)
        approved = next(r.id for r in chosen if r.kind == "relationship" and r.data["conduit_decision"] == "Approved")
        self.assertLess(ids.index(external), ids.index(approved))
        self.assertLess(ids.index(unexpected), ids.index(approved))
        # both endpoints of every relationship sent are also sent, right after it
        for r in chosen:
            if r.kind == "relationship":
                for key in ("endpoint_a_id", "endpoint_b_id"):
                    if r.data.get(key):
                        self.assertIn(r.data[key], ids)

    def test_selection_for_a_named_asset_pulls_its_relationships_and_flows(self):
        chosen = self.ev.select("Why is HIST-01 interesting?")
        ids = [r.id for r in chosen]
        self.assertEqual(ids[0], "ASSET-003")
        self.assertIn("FLOW-008", ids)
        chosen = self.ev.select("What is 10.10.20.99 doing?")
        self.assertEqual(chosen[0].id, "ASSET-002")

    def test_executive_question_gets_findings_and_captures(self):
        ids = [r.id for r in self.ev.select("Summarize this environment for an executive audience.")]
        self.assertIn("FND-01", ids)
        self.assertIn("CAP-001", ids)

    def test_budget_is_respected(self):
        chosen = self.ev.select(STANDARD_QUESTIONS[0], budget=1200)
        self.assertTrue(chosen)
        self.assertLessEqual(sum(len(r.text()) + 1 for r in chosen), 1200)
        one = self.ev.select(STANDARD_QUESTIONS[0], budget=10)
        self.assertEqual(len(one), 1)  # never sends nothing

    def test_prompt_contains_context_evidence_and_question(self):
        records = self.ev.select("x")
        prompt = build_user_prompt("Which relationships matter?", self.ev.context, records)
        self.assertIn("Test Plant", prompt)
        self.assertIn(f"EVIDENCE ({len(records)} records", prompt)
        self.assertIn("Which relationships matter?", prompt)
        for r in records:
            self.assertIn(f'"id": "{r.id}"', prompt)


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.ev = Evidence(export())
        self.records = self.ev.select(STANDARD_QUESTIONS[0])

    def test_grounded_reply_passes(self):
        parsed, check = validate(GOOD_REPLY, self.records, self.ev.context)
        self.assertIsNotNone(parsed)
        self.assertTrue(check.grounded, check.summary())
        self.assertEqual(check.missing_keys, [])
        self.assertIn("REL-002", check.cited_ids)

    def test_invented_evidence_and_addresses_are_flagged(self):
        parsed, check = validate(BAD_REPLY, self.records, self.ev.context)
        self.assertIsNotNone(parsed)
        self.assertFalse(check.grounded)
        self.assertEqual(check.unsupported_ids, ["REL-042"])
        self.assertEqual(check.unsupported_ips, ["192.168.77.5"])
        self.assertIn("REL-042", check.summary())

    def test_json_recovery_from_fences_and_prose(self):
        self.assertEqual(parse_json_reply('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(parse_json_reply('Here you go: {"a": 1} hope that helps'), {"a": 1})
        self.assertIsNone(parse_json_reply("no json here"))
        self.assertIsNone(parse_json_reply("[1, 2]"))
        parsed, check = validate("I cannot answer that.", self.records)
        self.assertIsNone(parsed)
        self.assertFalse(check.parsed)
        self.assertEqual(check.summary(), "response was not valid JSON")

    def test_missing_keys_reported(self):
        parsed, check = validate('{"analysis": "x", "evidence_ids": ["ASSET-001"]}', self.records)
        self.assertTrue(check.parsed)
        self.assertIn("observed_facts", check.missing_keys)
        self.assertIn("confidence", check.missing_keys)


class CopilotTests(unittest.TestCase):
    def test_ask_logs_and_renders(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "log.jsonl"
            backend = ScriptedBackend([GOOD_REPLY, BAD_REPLY])
            copilot = Copilot(export(), backend, log, log_prompts=True)
            tokens = []
            first = copilot.ask(STANDARD_QUESTIONS[0], tokens.append)
            second = copilot.ask("Draft a finding for the external path.")
            self.assertTrue(tokens)
            self.assertTrue(first.validation.grounded)
            self.assertFalse(second.validation.grounded)
            self.assertIn("Observed facts", first.render())
            self.assertIn("Confidence: medium", first.render())
            system, user = backend.calls[0]
            self.assertIn("Use only the evidence supplied", system)
            self.assertIn(STANDARD_QUESTIONS[0], user)
            rows = [json.loads(l) for l in log.read_text().splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["backend"], "scripted")
            self.assertTrue(rows[0]["grounded"])
            self.assertFalse(rows[1]["grounded"])
            self.assertIn("prompt", rows[0])
            self.assertEqual(rows[0]["evidence_ids"], first.evidence_ids)
            summary = summarize_log(log)
            self.assertEqual(summary[0]["answers"], 2)
            self.assertEqual(summary[0]["grounded"], 1)
            self.assertEqual(summary[0]["parsed_json"], 2)

    def test_unparseable_reply_is_kept_verbatim(self):
        copilot = Copilot(export(), ScriptedBackend(["Sorry, I can't."]))
        answer = copilot.ask("anything")
        self.assertIsNone(answer.reply)
        self.assertEqual(answer.render(), "Sorry, I can't.")
        self.assertFalse(answer.validation.grounded)


class BackendFactoryTests(unittest.TestCase):
    def test_defaults_and_overrides(self):
        b = make_backend("ollama")
        self.assertEqual((b.name, b.model, b.url), ("ollama", "qwen2.5:7b", "http://127.0.0.1:11434"))
        b = make_backend("llamacpp", url="http://10.0.0.5:8080/")
        self.assertEqual(b.url, "http://10.0.0.5:8080")
        b = make_backend("openai", model="gpt-4o", api_key="k", json_mode=False)
        self.assertEqual((b.model, b.api_key, b.json_mode), ("gpt-4o", "k", False))
        b = make_backend("anthropic", api_key="k")
        self.assertEqual(b.url, "https://api.anthropic.com")
        with self.assertRaises(BackendError):
            make_backend("gemini")

    def test_unreachable_backend_raises_backend_error(self):
        b = make_backend("ollama", url="http://127.0.0.1:9", timeout=2)
        with self.assertRaises(BackendError):
            b.chat("s", "u")


if __name__ == "__main__":
    unittest.main()


import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _FakeLLM(BaseHTTPRequestHandler):
    """Speaks just enough Ollama NDJSON, OpenAI SSE and Anthropic SSE to exercise the stream parsers."""
    seen: list[dict] = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _FakeLLM.seen.append({"path": self.path, "body": body, "headers": {k.lower(): v for k, v in self.headers.items()}})
        self.send_response(200); self.send_header("Content-Type", "application/x-ndjson"); self.end_headers()
        if self.path == "/api/chat":
            for tok in ('{"a"', ': 1}'):
                self.wfile.write((json.dumps({"model": "qwen-test", "message": {"role": "assistant", "content": tok}, "done": False}) + "\n").encode())
            self.wfile.write((json.dumps({"model": "qwen-test", "message": {"content": ""}, "done": True, "prompt_eval_count": 321, "eval_count": 7}) + "\n").encode())
        elif self.path == "/v1/chat/completions":
            for tok in ('{"a"', ': 1}'):
                self.wfile.write(("data: " + json.dumps({"model": "gpt-test", "choices": [{"delta": {"content": tok}}]}) + "\n\n").encode())
            self.wfile.write(("data: " + json.dumps({"model": "gpt-test", "choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 3}}) + "\n\n").encode())
            self.wfile.write(b"data: [DONE]\n\n")
        elif self.path == "/v1/messages":
            self.wfile.write(("data: " + json.dumps({"type": "message_start", "message": {"model": "claude-test", "usage": {"input_tokens": 50}}}) + "\n\n").encode())
            for tok in ('{"a"', ': 1}'):
                self.wfile.write(("data: " + json.dumps({"type": "content_block_delta", "delta": {"type": "text_delta", "text": tok}}) + "\n\n").encode())
            self.wfile.write(("data: " + json.dumps({"type": "message_delta", "usage": {"output_tokens": 4}}) + "\n\n").encode())
        else:
            self.wfile.write(b"{}")


class StreamingBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _FakeLLM)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _run(self, name, **kw):
        _FakeLLM.seen.clear()
        tokens = []
        result = make_backend(name, url=self.url, **kw).chat("SYS", "USER", tokens.append)
        self.assertEqual(result.text, '{"a": 1}')
        self.assertEqual(tokens, ['{"a"', ': 1}'])
        self.assertIsNotNone(result.first_token_seconds)
        return result, _FakeLLM.seen[0]

    def test_ollama_stream(self):
        result, req = self._run("ollama", model="qwen-test")
        self.assertEqual((result.model, result.prompt_tokens, result.completion_tokens, result.backend), ("qwen-test", 321, 7, "ollama"))
        self.assertEqual(req["body"]["format"], "json")
        self.assertEqual(req["body"]["messages"][0], {"role": "system", "content": "SYS"})

    def test_openai_compatible_stream(self):
        result, req = self._run("openai", model="gpt-test", api_key="sk-test")
        self.assertEqual((result.model, result.prompt_tokens, result.completion_tokens), ("gpt-test", 11, 3))
        self.assertEqual(req["headers"]["authorization"], "Bearer sk-test")
        self.assertEqual(req["body"]["response_format"], {"type": "json_object"})

    def test_llamacpp_is_openai_compatible_without_a_key(self):
        result, req = self._run("llamacpp", json_mode=False)
        self.assertEqual(result.backend, "llamacpp")
        self.assertNotIn("authorization", req["headers"])
        self.assertNotIn("response_format", req["body"])

    def test_anthropic_stream(self):
        result, req = self._run("anthropic", model="claude-test", api_key="sk-ant")
        self.assertEqual((result.model, result.prompt_tokens, result.completion_tokens), ("claude-test", 50, 4))
        self.assertEqual(req["headers"]["x-api-key"], "sk-ant")
        self.assertEqual(req["body"]["system"], "SYS")
        self.assertEqual(req["body"]["messages"], [{"role": "user", "content": "USER"}])

    def test_anthropic_without_key_fails_fast(self):
        import os
        saved = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with self.assertRaises(BackendError):
                make_backend("anthropic", url=self.url).chat("s", "u")
        finally:
            if saved is not None:
                os.environ["ANTHROPIC_API_KEY"] = saved
