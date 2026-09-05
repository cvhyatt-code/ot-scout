"""Assessment copilot: a language model reasoning over OT Scout evidence — never creating it.

Design rules (see ASSESSMENT_GUIDE.md, "Copilot"):

  1. OT Scout's deterministic analysis is the source of truth. The model is handed a slice of
     the assessment export, each record carrying a stable evidence identifier (ASSET-007,
     REL-012, CAP-001, FND-02, SITE-002), and is told to reason only about what it was given.
  2. Every answer must come back as structured JSON that separates observed fact, inference,
     potential concern, alternative explanation and validation step, and must cite the
     evidence identifiers it relied on.
  3. The answer is checked, not trusted: evidence identifiers the model cites but was never
     given, and IP addresses or MAC addresses in its text that appear nowhere in the supplied
     evidence, are flagged as unsupported. That flag is the hallucination meter for the
     evaluation phase.
  4. Only the evidence relevant to the question is sent, within a character budget, because
     a 7B model on a CPU reads its prompt at a few dozen tokens a second.
  5. Every exchange is appended to a JSONL log with backend, model, evidence sent, latency and
     validation results, so models and prompt revisions can be compared side by side.

The module reads an assessment export (`/api/export/assessment.json` or `Store.json_export()`)
and talks to a backend from `llm_backends`. It does not touch capture, parsing or the store.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .llm_backends import Backend, ChatResult

SYSTEM_PROMPT = """You are an OT/ICS cybersecurity assessment assistant working alongside a human assessor.

You are given EVIDENCE collected by OT Scout, a passive network assessment tool. Every evidence record has an identifier such as ASSET-007, REL-012, FLOW-042, CAP-001, SITE-002 or FND-03.

Rules you must follow:
1. Use only the evidence supplied below. Do not assume any device, protocol, relationship, vulnerability, configuration, firmware version, CVE, network path, security control, business impact or compliance requirement exists unless it appears in the evidence.
2. Never invent IP addresses, MAC addresses, host names, vendors or models. Only repeat ones that appear in the evidence.
3. Separate clearly: what was OBSERVED (fact), what you INFER from it, what the potential CONCERN is, what ALTERNATIVE benign explanations exist, and what the assessor should VALIDATE on site.
4. When the evidence is insufficient to answer, say so in "insufficient_evidence" rather than guessing.
5. Do not call anything a vulnerability, a compromise or a non-compliance unless the evidence supports that conclusion. Prefer "warrants validation".
6. Cite evidence identifiers for every fact and concern you state.
7. The assessor decides. You advise.

Passive-assessment context: OT Scout only sees traffic that crossed its collection point during the capture window. Absence of traffic is not proof of absence. Purdue levels were assigned by the assessor unless marked "Suggested". Conduit decisions come from the assessor: Approved, Tolerated, Unexpected, or Unknown (not yet reviewed).

Respond with a single JSON object and nothing else, using exactly this shape:
{
  "observed_facts": ["fact, citing evidence ids"],
  "analysis": "short assessor-style reasoning in plain English",
  "potential_concerns": ["concern, citing evidence ids"],
  "alternative_explanations": ["benign explanation"],
  "recommended_validation": ["specific thing to check or ask on site"],
  "evidence_ids": ["every identifier you relied on"],
  "confidence": "low|medium|high",
  "insufficient_evidence": ["what you would need to know to be more certain"]
}"""

OUTPUT_KEYS = ("observed_facts", "analysis", "potential_concerns", "alternative_explanations",
               "recommended_validation", "evidence_ids", "confidence", "insufficient_evidence")

STANDARD_QUESTIONS = [
    "Which observed relationships should I investigate first?",
    "Which assets appear to communicate outside their expected Purdue zone?",
    "Which observed devices are missing from the documented inventory?",
    "What should I ask the controls engineer based on this assessment?",
    "Identify the three most important areas requiring human validation.",
    "Draft a potential finding for the most significant undocumented or unexpected routed relationship.",
    "What evidence would I need before making the most significant unexpected relationship a formal finding?",
    "Summarize this environment for an executive audience.",
]

EVIDENCE_ID = re.compile(r"\b(ASSET|REL|FLOW|CAP|SITE|FND|OBS|POS)-\d{1,4}\b")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.IGNORECASE)

DEFAULT_BUDGET = 12000  # characters of evidence per prompt; ~3,000 tokens


# ------------------------------------------------------------------------------------------
# Evidence
# ------------------------------------------------------------------------------------------

@dataclass
class Record:
    id: str
    kind: str  # asset | relationship | flow | capture | site | finding
    data: dict
    priority: int = 50  # lower = more important when the budget is tight
    tags: set[str] = field(default_factory=set)

    def text(self) -> str:
        return json.dumps({"id": self.id, **self.data}, separators=(", ", ": "), ensure_ascii=False)


def _clean(values: dict) -> dict:
    """Drop empty fields so evidence lines stay short. Booleans and packet counts are kept."""
    return {k: v for k, v in values.items() if isinstance(v, bool) or k == "packets" or v not in (None, "", [], {}, 0)}


class Evidence:
    """The assessment export normalised into compact, identified records."""

    def __init__(self, export: dict):
        self.export = export
        self.records: dict[str, Record] = {}
        self.assets_by_id: dict[int, str] = {}
        self.asset_names: dict[str, str] = {}
        self.context = self._context()
        self._assets()
        self._relationships()
        self._flows()
        self._captures()
        self._sites()
        self._findings()

    # -- building -----------------------------------------------------------------------
    def _context(self) -> dict:
        summary = self.export.get("summary") or {}
        zones = self.export.get("zones") or {}
        sessions = self.export.get("sessions") or []
        levels = {name: info.get("assets", 0) for name, info in (zones.get("levels") or {}).items() if info.get("assets")}
        assessment = next((s.get("assessment") for s in sessions if s.get("assessment")), "")
        sites = sorted({s.get("site") for s in sessions if s.get("site")})
        return _clean({"assessment": assessment, "sites_captured": sites, "capture_sessions": len(sessions),
                       "assets": summary.get("assets"), "relationships": summary.get("relationships"),
                       "flows": summary.get("flows"), "packets": summary.get("packets"),
                       "assets_per_purdue_level": levels, "levels_unassigned": (zones.get("physical") or 0) - (zones.get("assigned") or 0),
                       "findings_in_register": len(self.export.get("findings") or [])})

    def _assets(self):
        for a in self.export.get("assets") or []:
            rid = f"ASSET-{int(a['id']):03d}"
            self.assets_by_id[int(a["id"])] = rid
            observed_only = (a.get("source") or "Passive capture") == "Passive capture"
            silent = a.get("classification") == "Documented, not observed"
            context_fields = ("location", "criticality", "purdue_level", "zone", "process_function", "owner")
            no_context = not any(a.get(k) for k in context_fields)
            data = _clean({
                "name": a.get("name"), "type": a.get("display_type") or a.get("auto_type"),
                "type_confidence": a.get("type_confidence"), "type_evidence": a.get("type_evidence"), "type_source": a.get("type_source"),
                "manufacturer": a.get("manufacturer") or a.get("vendor"), "model": a.get("model"), "firmware": a.get("firmware"),
                "ips": a.get("ips"), "mac": a.get("mac") if not str(a.get("mac", "")).startswith("manual:") else "",
                "classification": a.get("classification"), "purdue_level": a.get("purdue_level"), "purdue_source": a.get("purdue_source"),
                "suggested_level": a.get("suggested_level") if not a.get("purdue_level") else "", "zone": a.get("zone"),
                "criticality": a.get("criticality"), "process_function": a.get("process_function"), "location": a.get("location"),
                "owner": a.get("owner"), "documentation_source": a.get("source") or "Passive capture",
                "documented": not observed_only, "observed_in_traffic": not silent and bool(a.get("packets")),
                "observed_protocols": a.get("observed_protocols"), "packets": a.get("packets"),
                "support_status": a.get("support_status"), "end_of_support": a.get("end_of_support"),
                "patch_status": a.get("patch_status"), "backup_status": a.get("backup_status"),
                "exposure": a.get("exposure"), "exposure_band": a.get("exposure_band"),
                "exposure_factors": [re.sub(r"\s*\(\+\d+\)$", "", f) for f in (a.get("exposure_factors") or [])[:4]],
                "notes": (a.get("notes") or "")[:200],
            })
            tags = {"asset"}
            priority = 60
            if observed_only or no_context:
                tags.add("undocumented"); priority = 25
            if (a.get("type_confidence") or 0) < 60 and not a.get("type_source", "").startswith("Assessor"):
                tags.add("low_confidence_type"); priority = min(priority, 35)
            if not a.get("purdue_level"):
                tags.add("level_unassigned"); priority = min(priority, 35)
            if a.get("exposure_band") in ("High", "Critical"):
                tags.add("high_exposure"); priority = min(priority, 30)
            if a.get("support_status") in ("End of support", "End of life"):
                tags.add("lifecycle")
            if "not client asset" in (a.get("display_type") or "").lower():
                tags = {"asset", "collector"}; priority = 90  # the assessor's own laptop is never a finding
            rec = Record(rid, "asset", data, priority, tags)
            self.records[rid] = rec
            for key in filter(None, [a.get("name"), a.get("mac")] + [ip.strip() for ip in str(a.get("ips") or "").split(",")]):
                self.asset_names[str(key).lower()] = rid

    def _relationships(self):
        rels = self.export.get("relationships") or []
        ordered = sorted(rels, key=lambda r: (r.get("key_a", ""), r.get("key_b", ""), r.get("protocols", "")))
        for n, r in enumerate(ordered, 1):
            rid = f"REL-{n:03d}"
            decision = r.get("decision") or "Unknown"
            data = _clean({
                "endpoint_a": r.get("endpoint_a"), "endpoint_a_id": self._asset_ref(r.get("key_a")),
                "endpoint_b": r.get("endpoint_b"), "endpoint_b_id": self._asset_ref(r.get("key_b")),
                "protocols": r.get("protocols"), "level_a": r.get("level_a"), "level_b": r.get("level_b"),
                "boundary_crossing": r.get("crossing") or "none (same level)", "conduit_decision": decision,
                "documented_purpose": r.get("purpose"), "category": r.get("category"), "external_ips": r.get("external_ips"),
                "flows": r.get("flows"), "packets": r.get("packets"), "collection_point": r.get("collection_point"),
                "first_seen": r.get("first_seen"), "last_seen": r.get("last_seen"),
            })
            tags = {"relationship"}
            priority = 55
            if r.get("crossing"):
                tags.add("crossing"); priority = 40
            if decision == "Unexpected":
                tags.add("unexpected"); priority = 10
            elif decision == "Unknown":
                tags.add("unreviewed"); priority = 20
            elif decision == "Tolerated":
                tags.add("tolerated"); priority = 30
            if "external" in (r.get("crossing") or "").lower() or "external" in (r.get("category") or "").lower() or r.get("external_ips"):
                tags.add("external"); priority = min(priority, 15)
            if "bypass" in (r.get("crossing") or "").lower():
                tags.add("dmz_bypass"); priority = min(priority, 12)
            self.records[rid] = Record(rid, "relationship", data, priority, tags)

    def _asset_ref(self, key: str | None) -> str:
        if key and key.startswith("asset:"):
            try:
                return self.assets_by_id.get(int(key.split(":", 1)[1]), "")
            except ValueError:
                return ""
        return ""

    def _flows(self):
        flows = self.export.get("flows") or []
        for f in flows:
            rid = f"FLOW-{int(f['id']):03d}"
            data = _clean({"src": f.get("src_name") or f.get("src_ip"), "src_ip": f.get("src_ip"), "dst": f.get("dst_name") or f.get("dst_ip"),
                           "dst_ip": f.get("dst_ip"), "transport": f.get("transport"), "dst_port": f.get("dst_port"),
                           "protocol": f.get("app_protocol"), "scope": f.get("traffic_scope"), "packets": f.get("packets"),
                           "collection_point": f.get("collection_point"), "first_seen": f.get("first_seen"), "last_seen": f.get("last_seen")})
            tags = {"flow"}
            priority = 70
            dst = str(f.get("dst_ip") or "")
            if dst and not _private(dst) and f.get("traffic_scope") == "Unicast":
                tags.add("external"); priority = 45
            self.records[rid] = Record(rid, "flow", data, priority, tags)

    def _captures(self):
        for s in self.export.get("sessions") or []:
            rid = f"CAP-{int(s['id']):03d}"
            data = _clean({"site": s.get("site"), "collection_point": s.get("collection_point"), "access_method": s.get("access_method"),
                           "started_at": s.get("started_at"), "duration": s.get("duration"), "packets": s.get("packets"),
                           "dropped_frames": s.get("dropped"), "local_unicast": s.get("local_unicast"),
                           "third_party_unicast": s.get("third_party_unicast"), "broadcast_multicast": s.get("broadcast_multicast"),
                           "source_type": s.get("source_type")})
            tags = {"capture"}
            if s.get("dropped"):
                tags.add("dropped_frames")
            self.records[rid] = Record(rid, "capture", data, 50, tags)

    def _sites(self):
        for s in self.export.get("sites") or []:
            rid = f"SITE-{int(s['id']):03d}"
            checklist = s.get("checklist") or []
            incomplete = [c.get("label") for c in checklist if c.get("status") not in ("Complete", "Not applicable")]
            legs = s.get("legs") or []
            data = _clean({"name": s.get("name"), "facility_type": s.get("facility_type"), "operational_function": s.get("operational_function"),
                           "walkdown_date": s.get("walkdown_date"), "documentation_available": s.get("documentation"),
                           "deviations_noted_on_walkdown": s.get("deviations"), "checklist_items_incomplete": incomplete,
                           "network_legs": [_clean({"name": l.get("name"), "kind": l.get("kind"), "evidence_source": l.get("evidence_source")}) for l in legs][:12]})
            tags = {"site"}
            if s.get("deviations") or incomplete:
                tags.add("gaps")
            self.records[rid] = Record(rid, "site", data, 45, tags)

    def _findings(self):
        for f in self.export.get("findings") or []:
            ref = f.get("ref") or f"FND-{int(f['id']):02d}"
            data = _clean({"title": f.get("title"), "kind": f.get("kind"), "rating": f.get("rating"), "confidence": f.get("confidence"),
                           "condition": f.get("condition"), "evidence": f.get("evidence"), "recommendation": f.get("recommendation"),
                           "status": "validated by assessor"})
            tags = {"finding"}
            priority = 65 if f.get("rating") in ("Positive", "Informational") else 50
            self.records[ref] = Record(ref, "finding", data, priority, tags)

    # -- selection ----------------------------------------------------------------------
    def by_tag(self, *tags: str, kind: str | None = None) -> list[Record]:
        out = [r for r in self.records.values() if (kind is None or r.kind == kind) and any(t in r.tags for t in tags)]
        return sorted(out, key=lambda r: (r.priority, r.id))

    def kind(self, kind: str) -> list[Record]:
        return sorted((r for r in self.records.values() if r.kind == kind), key=lambda r: (r.priority, r.id))

    def mentioned_assets(self, question: str) -> list[Record]:
        q = question.lower()
        hits: list[str] = []
        for key, rid in self.asset_names.items():
            if len(key) >= 4 and key in q and rid not in hits:
                hits.append(rid)
        for m in EVIDENCE_ID.finditer(question):
            if m.group(0) in self.records and m.group(0) not in hits:
                hits.append(m.group(0))
        return [self.records[r] for r in hits]

    def related(self, asset: Record) -> list[Record]:
        out = []
        ips = {ip.strip() for ip in str(asset.data.get("ips") or "").split(",") if ip.strip()}
        for r in self.records.values():
            if r.kind == "relationship" and asset.id in (r.data.get("endpoint_a_id"), r.data.get("endpoint_b_id")):
                out.append(r)
            elif r.kind == "flow" and ips and (r.data.get("src_ip") in ips or r.data.get("dst_ip") in ips):
                out.append(r)
        return sorted(out, key=lambda r: (r.priority, r.id))

    def select(self, question: str, budget: int = DEFAULT_BUDGET) -> list[Record]:
        """Pick the evidence a question needs, most important first, within the character budget."""
        q = question.lower()
        chosen: list[Record] = []

        def add(records):
            for r in records:
                if r not in chosen and "collector" not in r.tags:
                    chosen.append(r)
                    if r.kind == "relationship":  # the model must be able to see both ends of any relationship
                        for key in ("endpoint_a_id", "endpoint_b_id"):
                            end = self.records.get(r.data.get(key, ""))
                            if end and end not in chosen:
                                chosen.append(end)

        specific = self.mentioned_assets(question)
        if specific:
            add(specific)
            for a in specific:
                add(self.related(a))

        topics = {
            "investigate": any(w in q for w in ("investigate", "priorit", "first", "important", "validation", "validate", "review", "attention", "next")),
            "purdue": any(w in q for w in ("purdue", "zone", "level", "boundary", "cross", "segment", "conduit", "dmz")),
            "documented": any(w in q for w in ("document", "inventory", "missing", "drawing", "undocumented", "unknown device", "unexpected device", "walkdown")),
            "interview": any(w in q for w in ("ask", "engineer", "question", "interview", "walkthrough", "photograph", "administrator", "operator")),
            "finding": any(w in q for w in ("finding", "draft", "formal", "write up", "write-up", "evidence would", "report language")),
            "executive": any(w in q for w in ("executive", "summar", "plant manager", "overview", "plain english", "leadership", "board")),
            "external": any(w in q for w in ("external", "internet", "third party", "third-party", "remote", "vendor access", "cloud", "outbound")),
            "lifecycle": any(w in q for w in ("end of life", "end-of-life", "end of support", "obsolete", "patch", "backup", "firmware")),
            "capture": any(w in q for w in ("capture", "session", "coverage", "collection point", "span", "dropped")),
        }
        if topics["external"]:
            add(self.by_tag("external"))
        if topics["investigate"] or topics["finding"]:
            add(self.by_tag("unexpected", "dmz_bypass", "external", "unreviewed", kind="relationship"))
            add(self.by_tag("external", kind="flow"))
            add(self.by_tag("undocumented", "high_exposure", kind="asset"))
            add(self.by_tag("tolerated", kind="relationship"))
        if topics["purdue"]:
            add(self.by_tag("crossing", kind="relationship"))
            add(self.by_tag("level_unassigned", kind="asset"))
        if topics["documented"]:
            add(self.by_tag("undocumented", "low_confidence_type", kind="asset"))
            add(self.by_tag("unreviewed", kind="relationship"))
            add(self.kind("site"))
        if topics["interview"]:
            add(self.by_tag("unexpected", "unreviewed", "tolerated", kind="relationship"))
            add(self.by_tag("undocumented", "low_confidence_type", "level_unassigned", kind="asset"))
            add(self.kind("site"))
        if topics["lifecycle"]:
            add(self.by_tag("lifecycle", "high_exposure", kind="asset"))
        if topics["capture"]:
            add(self.kind("capture"))
            add(self.kind("site"))
        if topics["executive"]:
            add(self.kind("finding"))
            add(self.kind("capture"))
            add(self.by_tag("unexpected", "dmz_bypass", "external", kind="relationship"))
            add(self.by_tag("high_exposure", kind="asset"))
        if topics["finding"]:
            add([r for r in self.kind("finding") if r.data.get("rating") not in ("Positive", "Informational")])
        if not chosen:  # nothing matched: the general triage set
            add(self.by_tag("unexpected", "dmz_bypass", "external", "unreviewed", kind="relationship"))
            add(self.by_tag("undocumented", "high_exposure", "level_unassigned", kind="asset"))
            add(self.kind("capture"))

        # Fill remaining budget with the rest of the assets and relationships, most important first.
        remainder = sorted((r for r in self.records.values() if r not in chosen and r.kind in ("asset", "relationship") and "collector" not in r.tags),
                           key=lambda r: (r.priority, r.id))
        chosen.extend(remainder)
        return self._fit(chosen, budget)

    @staticmethod
    def _fit(records: list[Record], budget: int) -> list[Record]:
        out, used = [], 0
        for r in records:
            size = len(r.text()) + 1
            if used + size > budget:
                if not out:  # always send at least one record, even if it is over budget
                    out.append(r)
                continue
            out.append(r)
            used += size
        return out

    def stats(self) -> dict:
        kinds: dict[str, int] = {}
        for r in self.records.values():
            kinds[r.kind] = kinds.get(r.kind, 0) + 1
        return {"records": len(self.records), **kinds,
                "undocumented_assets": len(self.by_tag("undocumented", kind="asset")),
                "unexpected_relationships": len(self.by_tag("unexpected", kind="relationship")),
                "unreviewed_relationships": len(self.by_tag("unreviewed", kind="relationship")),
                "external_relationships": len(self.by_tag("external", kind="relationship")),
                "levels_unassigned": len(self.by_tag("level_unassigned", kind="asset"))}


def _private(ip: str) -> bool:
    try:
        a, b, *_ = (int(x) for x in ip.split("."))
    except ValueError:
        return True
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127 or (a == 169 and b == 254) or a >= 224


# ------------------------------------------------------------------------------------------
# Prompt, validation, logging
# ------------------------------------------------------------------------------------------

def build_user_prompt(question: str, context: dict, records: list[Record]) -> str:
    lines = ["ASSESSMENT CONTEXT", json.dumps(context, separators=(", ", ": "), ensure_ascii=False), "",
             f"EVIDENCE ({len(records)} records; one JSON object per line; only these may be cited)"]
    lines += [r.text() for r in records]
    lines += ["", "QUESTION", question.strip(), "",
              "Answer as the JSON object described in your instructions. Cite evidence ids. Do not mention any address, name or device that is not in the evidence above."]
    return "\n".join(lines)


@dataclass
class Validation:
    parsed: bool
    missing_keys: list[str]
    unsupported_ids: list[str]
    unsupported_ips: list[str]
    unsupported_macs: list[str]
    cited_ids: list[str]

    @property
    def grounded(self) -> bool:
        return self.parsed and not self.unsupported_ids and not self.unsupported_ips and not self.unsupported_macs

    def summary(self) -> str:
        if not self.parsed:
            return "response was not valid JSON"
        problems = []
        if self.missing_keys:
            problems.append(f"missing keys: {', '.join(self.missing_keys)}")
        if self.unsupported_ids:
            problems.append(f"cited evidence that was not supplied: {', '.join(self.unsupported_ids)}")
        if self.unsupported_ips:
            problems.append(f"IPs not in evidence: {', '.join(self.unsupported_ips)}")
        if self.unsupported_macs:
            problems.append(f"MACs not in evidence: {', '.join(self.unsupported_macs)}")
        return "grounded — every id, IP and MAC traces to supplied evidence" if not problems else "; ".join(problems)


def parse_json_reply(text: str) -> dict | None:
    """Accept a bare JSON object, or one wrapped in prose / a ```json fence — small models do that."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            value = json.loads(text[start:end + 1])
            return value if isinstance(value, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def validate(reply_text: str, records: list[Record], context: dict | None = None) -> tuple[dict | None, Validation]:
    parsed = parse_json_reply(reply_text)
    supplied_ids = {r.id for r in records}
    supplied_text = " ".join(r.text() for r in records) + " " + json.dumps(context or {})
    supplied_ips = set(IPV4.findall(supplied_text))
    supplied_macs = {m.lower() for m in MAC.findall(supplied_text)}
    cited = sorted({m.group(0) for m in EVIDENCE_ID.finditer(reply_text)})
    if parsed and isinstance(parsed.get("evidence_ids"), list):
        cited = sorted(set(cited) | {str(x) for x in parsed["evidence_ids"] if EVIDENCE_ID.fullmatch(str(x))})
    unsupported_ids = sorted(i for i in cited if i not in supplied_ids)
    reply_ips = set(IPV4.findall(reply_text))
    unsupported_ips = sorted(ip for ip in reply_ips if ip not in supplied_ips and not _looks_like_version(ip))
    unsupported_macs = sorted({m.lower() for m in MAC.findall(reply_text)} - supplied_macs)
    missing = [k for k in OUTPUT_KEYS if parsed is not None and k not in parsed]
    return parsed, Validation(parsed is not None, missing, unsupported_ids, unsupported_ips, unsupported_macs, cited)


def _looks_like_version(value: str) -> bool:
    """'1.2.3.4' in a reply is more likely a firmware string than an address; don't flag it."""
    parts = [int(p) for p in value.split(".")]
    return parts[0] < 10 and all(p < 20 for p in parts)


@dataclass
class Answer:
    question: str
    backend: str
    model: str
    evidence_ids: list[str]
    prompt_chars: int
    reply_text: str
    reply: dict | None
    validation: Validation
    latency_seconds: float
    first_token_seconds: float | None
    prompt_tokens: int | None
    completion_tokens: int | None
    timestamp: str

    def to_log(self, include_prompt: str | None = None) -> dict:
        row = asdict(self)
        row["grounded"] = self.validation.grounded
        if include_prompt is not None:
            row["prompt"] = include_prompt
        return row

    def render(self) -> str:
        """Plain-text rendering for the terminal."""
        if not self.reply:
            return self.reply_text
        r = self.reply
        out = []

        def section(title, items):
            if items:
                out.append(title)
                out.extend(f"  - {i}" for i in (items if isinstance(items, list) else [items]))
                out.append("")

        section("Observed facts", r.get("observed_facts"))
        if r.get("analysis"):
            out += ["Analysis", f"  {r['analysis']}", ""]
        section("Potential concerns", r.get("potential_concerns"))
        section("Alternative explanations", r.get("alternative_explanations"))
        section("Recommended validation", r.get("recommended_validation"))
        section("Insufficient evidence", r.get("insufficient_evidence"))
        out.append(f"Confidence: {r.get('confidence', '?')}    Evidence: {', '.join(str(x) for x in r.get('evidence_ids', []))}")
        return "\n".join(out)


class Copilot:
    def __init__(self, export: dict, backend: Backend, log_path: str | Path | None = None, budget: int = DEFAULT_BUDGET,
                 log_prompts: bool = False, system_prompt: str = SYSTEM_PROMPT):
        self.evidence = Evidence(export)
        self.backend = backend
        self.log_path = Path(log_path) if log_path else None
        self.budget = budget
        self.log_prompts = log_prompts
        self.system_prompt = system_prompt

    def prompt_for(self, question: str) -> tuple[str, list[Record]]:
        records = self.evidence.select(question, self.budget)
        return build_user_prompt(question, self.evidence.context, records), records

    def ask(self, question: str, on_token=None) -> Answer:
        user_prompt, records = self.prompt_for(question)
        result: ChatResult = self.backend.chat(self.system_prompt, user_prompt, on_token)
        reply, validation = validate(result.text, records, self.evidence.context)
        answer = Answer(question, result.backend, result.model, [r.id for r in records], len(self.system_prompt) + len(user_prompt),
                        result.text, reply, validation, round(result.latency_seconds, 2),
                        round(result.first_token_seconds, 2) if result.first_token_seconds is not None else None,
                        result.prompt_tokens, result.completion_tokens, time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        self._log(answer, user_prompt)
        return answer

    def _log(self, answer: Answer, user_prompt: str):
        if not self.log_path:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(answer.to_log(user_prompt if self.log_prompts else None), ensure_ascii=False) + "\n")


def load_export(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def export_from_database(db_path: str | Path) -> dict:
    from .store import Store
    return json.loads(Store(db_path).json_export())


def summarize_log(path: str | Path) -> list[dict]:
    """Per backend/model: answers, grounded share, JSON-parse share, median latency. For comparing models."""
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    groups: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        groups.setdefault((row["backend"], row["model"]), []).append(row)
    out = []
    for (backend, model), items in sorted(groups.items()):
        lat = sorted(r["latency_seconds"] for r in items)
        out.append({"backend": backend, "model": model, "answers": len(items),
                    "parsed_json": sum(1 for r in items if r["validation"]["parsed"]),
                    "grounded": sum(1 for r in items if r.get("grounded")),
                    "median_latency_s": lat[len(lat) // 2] if lat else None,
                    "median_first_token_s": (lambda v: v[len(v) // 2] if v else None)(sorted(r["first_token_seconds"] for r in items if r.get("first_token_seconds") is not None))})
    return out
