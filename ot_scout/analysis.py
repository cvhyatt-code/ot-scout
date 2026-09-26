"""What the evidence says, before anyone writes it up.

Draft findings (observations generated from the evidence) and the snapshot they are computed from.
Every number here comes from the store; narrative text is templated and marked for assessor
validation. Rendering the analysis into a document is somebody else's job.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .frameworks import refs_for
from .modules import contribute


OT_PROTOCOLS = {
    "MODBUS-TCP": "Modbus/TCP", "DNP3": "DNP3", "OPC-UA": "OPC UA", "S7COMM": "Siemens S7comm",
    "ETHERNET-IP": "EtherNet/IP (explicit)", "ETHERNET-IP-IO": "EtherNet/IP (implicit I/O)",
    "BACNET-IP": "BACnet/IP", "MQTT": "MQTT", "MQTT-TLS": "MQTT over TLS",
    "PROFINET-DCP": "Profinet DCP (discovery)", "PROFINET-RT": "Profinet RT (cyclic I/O)",
}
IT_SERVICE_PROTOCOLS = {
    "SMB": "SMB/CIFS", "RDP": "RDP", "VNC": "VNC", "SSH": "SSH", "TELNET": "Telnet", "FTP": "FTP",
    "TFTP": "TFTP", "SNMP": "SNMP", "HTTP": "HTTP (cleartext)", "HTTPS": "HTTPS", "NTP": "NTP",
    "SYSLOG": "Syslog", "LDAP": "LDAP", "MS-RPC": "MS-RPC",
}
CLEARTEXT_RISK = {"TELNET", "FTP", "HTTP", "SNMP", "VNC", "TFTP"}

# ----------------------------------------------------------------------------- helpers
def fmt_int(value) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value or "")


def fmt_duration_words(seconds) -> str:
    if seconds is None:
        return "unknown"
    seconds = int(seconds)
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    return f"{minutes}m {secs}s"


def sanitize_mac(mac: str) -> str:
    parts = (mac or "").upper().split(":")
    if len(parts) != 6:
        return mac
    return ":".join(parts[:3] + ["XX", "XX", parts[5]])


def _duration_seconds(started: str, ended: str | None) -> int | None:
    try:
        start = datetime.fromisoformat(started)
        end = datetime.fromisoformat(ended) if ended else datetime.now(timezone.utc)
        return max(0, int((end - start).total_seconds()))
    except (TypeError, ValueError):
        return None


# ----------------------------------------------------------------------------- data model
def collect(store, coverage=None) -> dict:
    """Snapshot everything the analysis needs from a Store. Optional modules add their own sections."""
    assets = store.assets()
    data = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "summary": store.dashboard(),
            "sessions": store.sessions(), "assets": assets, "relationships": store.relationships(100000, assets),
            "discovery_traffic": store.discovery_traffic(100000), "flows": store.connections(100000),
            "findings": store.findings(), "zones": store.zone_summary(assets),
            "coverage": coverage or store.coverage()}
    contribute(store, data)
    return data


def derive_coverage(data: dict) -> dict:
    if data.get("coverage"):
        return data["coverage"]
    sessions = data.get("sessions") or []
    if not sessions:
        return {"level": "none", "message": "No collection has been performed."}
    latest = sessions[0]
    if latest.get("source_type") == "pcap":
        return {"level": "unknown", "message": "Imported PCAP visibility depends on its original capture point."}
    if latest.get("third_party_unicast", 0) >= 10:
        return {"level": "likely-mirror", "message": f"Third-party unicast traffic observed ({latest['third_party_unicast']} frames). Mirror/TAP visibility is likely, but coverage still requires validation."}
    if latest.get("packets"):
        return {"level": "limited", "message": "No meaningful third-party unicast traffic observed. This appears to be an ordinary access port or limited feed; inventory is incomplete."}
    return {"level": "none", "message": "No packets observed. Verify the interface, cabling and capture point."}



class Analysis:
    """Everything derived from the data, computed once so sections stay consistent."""

    def __init__(self, data: dict, sanitize: bool):
        self.data = data
        self.sanitize = sanitize
        self.summary = data.get("summary") or {}
        self.sessions = data.get("sessions") or []
        self.assets = data.get("assets") or []
        self.relationships = data.get("relationships") or []
        self.discovery = data.get("discovery_traffic") or []
        self.flows = data.get("flows") or []
        self.coverage = derive_coverage(data)
        self.site_records = data.get("sites") or []
        self.legs = [dict(leg, site=site.get("name", "")) for site in self.site_records for leg in (site.get("legs") or [])]
        self.legs_no_evidence = [l for l in self.legs if l.get("evidence_source") == "None yet" or l.get("status") in ("Planned", "Not accessible")]
        self.checklist_status: dict[str, list] = {}
        for site in self.site_records:
            for item in site.get("checklist") or []:
                self.checklist_status.setdefault(item["item"], []).append((site.get("name", ""), item))
        for s in self.sessions:
            if s.get("duration_seconds") is None:
                s["duration_seconds"] = _duration_seconds(s.get("started_at", ""), s.get("ended_at"))
        self.live_sessions = [s for s in self.sessions if s.get("source_type", "live") == "live"]
        self.total_duration = sum((s["duration_seconds"] or 0) for s in self.live_sessions)
        self.packets = sum(int(s.get("packets") or 0) for s in self.sessions)
        self.bytes = sum(int(s.get("bytes") or 0) for s in self.sessions)
        self.third_party = sum(int(s.get("third_party_unicast") or 0) for s in self.sessions)
        self.local_unicast = sum(int(s.get("local_unicast") or 0) for s in self.sessions)
        self.broadcast = sum(int(s.get("broadcast_multicast") or 0) for s in self.sessions)
        self.physical = [a for a in self.assets if a.get("physical_asset")]
        self.derived = [a for a in self.assets if not a.get("physical_asset")]
        self.access_methods = sorted({s.get("access_method", "") for s in self.sessions if s.get("access_method")})
        self.points = sorted({s.get("collection_point", "") for s in self.sessions})
        self.assessment_names = sorted({s.get("assessment", "") for s in self.sessions})
        self.sites = sorted({s.get("site", "") for s in self.sessions})
        self.categories: dict[str, dict] = {}
        for r in self.relationships:
            c = self.categories.setdefault(r.get("category", "Unicast"), {"count": 0, "packets": 0})
            c["count"] += 1; c["packets"] += int(r.get("packets") or 0)
        self.protocols: dict[str, dict] = {}
        for f in self.flows:
            p = self.protocols.setdefault(f.get("app_protocol") or "?", {"flows": 0, "packets": 0, "scope": set()})
            p["flows"] += 1; p["packets"] += int(f.get("packets") or 0); p["scope"].add(f.get("traffic_scope") or "")
        self.ot_seen = {k: v for k, v in self.protocols.items() if k in OT_PROTOCOLS}
        self.cleartext_seen = {k: v for k, v in self.protocols.items() if k in CLEARTEXT_RISK}
        # OPC UA servers and clients with their consolidated claims (highest-confidence value per field)
        self.opcua_servers, self.opcua_clients = [], []
        for a in self.physical:
            fp: dict[str, str] = {}
            conf: dict[str, int] = {}
            for f in a.get("fingerprints") or []:
                k, v, c = f.get("field", ""), f.get("value", ""), int(f.get("confidence") or 0)
                if k.startswith("opcua_") or k in ("software", "role"):
                    if k == "role":
                        if v in ("OPC UA server", "OPC UA client"):
                            fp.setdefault("roles", ""); fp["roles"] += v + ";"
                        continue
                    if c > conf.get(k, -1):
                        fp[k], conf[k] = v, c
            if "OPC UA server" in fp.get("roles", "") and any(k.startswith("opcua_") for k in fp):
                self.opcua_servers.append((a, fp))
            if "OPC UA client" in fp.get("roles", ""):
                self.opcua_clients.append((a, fp))
        # a client's endpoint claim was recorded on the server it named; find it back through relationships
        server_by_label = {self.label(x): fp.get("opcua_endpoint", "") for x, fp in self.opcua_servers}
        for x, fp in self.opcua_clients:
            targets = sorted({server_by_label[r["endpoint_b"] if r["endpoint_a"] == self.label(x) else r["endpoint_a"]] for r in self.relationships
                              if self.label(x) in (r["endpoint_a"], r["endpoint_b"]) and "OPC-UA" in (r.get("protocols") or "")
                              and (r["endpoint_b"] if r["endpoint_a"] == self.label(x) else r["endpoint_a"]) in server_by_label} - {""})
            fp["opcua_endpoint_target"] = ", ".join(targets)
        # OPC UA servers advertising an unencrypted channel or anonymous logon, and clients seen using either
        self.opcua_weak = []
        for a in self.physical:
            fps = {(f.get("field"), f.get("value")) for f in (a.get("fingerprints") or [])}
            issues = []
            if any(k == "opcua_security_policies" and "None" in (v or "").split(", ") for k, v in fps):
                issues.append("SecurityPolicy None offered")
            if any(k == "opcua_security_modes" and "None" in (v or "").split(", ") for k, v in fps):
                issues.append("MessageSecurityMode None offered")
            if any(k == "opcua_user_tokens" and "Anonymous" in (v or "") for k, v in fps):
                issues.append("anonymous logon accepted")
            if any(k == "opcua_auth" and v == "Anonymous" for k, v in fps):
                issues.append("client authenticated anonymously")
            if any(k == "opcua_security_policy" and v == "None" for k, v in fps):
                issues.append("channel opened with SecurityPolicy None")
            if issues:
                self.opcua_weak.append((a, sorted(set(issues))))
        self.undocumented = [a for a in self.physical if not any(a.get(k) for k in ("location", "criticality", "purdue_level", "zone", "process_function", "owner"))]
        self.overrides = [a for a in self.assets if a.get("manual_type")]
        self.external = [r for r in self.relationships if r.get("category") == "Asset-to-external/unknown"]
        self.local_pairs = [r for r in self.relationships if r.get("category") == "Local asset-to-asset"]
        self.type_counts: dict[str, int] = {}
        for a in self.physical:
            self.type_counts[a.get("display_type") or "Unclassified"] = self.type_counts.get(a.get("display_type") or "Unclassified", 0) + 1
        self.reduction = (1 - len(self.relationships) / len(self.flows)) * 100 if self.flows and self.relationships else 0.0
        self.subnets: dict[str, list[dict]] = {}
        for asset in self.physical:
            for ip in (asset.get("ips") or "").split(","):
                if "." in ip and ip.count(".") == 3:
                    self.subnets.setdefault(".".join(ip.split(".")[:3]) + ".0/24", []).append(asset)
        dominant = max(self.subnets, key=lambda k: len(self.subnets[k])) if self.subnets else ""
        self.minority_subnets = {k: v for k, v in self.subnets.items() if k != dominant} if len(self.subnets) > 1 else {}
        self.zones = data.get("zones") or {}
        self.documented = [a for a in self.physical if (a.get("source") or "Passive capture") != "Passive capture"]
        self.documented_only = [a for a in self.physical if a.get("classification") == "Documented, not observed"]
        self.eol = [a for a in self.physical if (a.get("support_status") or "").startswith("End")]
        self.no_backup = [a for a in self.physical if a.get("backup_status") in ("No backup", "Unknown") or ((a.get("criticality") in ("High", "Critical")) and not a.get("backup_status"))]
        self.lifecycle_rows = [a for a in self.physical if any(a.get(k) for k in ("install_date", "end_of_life", "end_of_support", "support_status", "patch_status", "backup_status", "last_backup"))]
        self.crossing_rels = [r for r in self.relationships if r.get("crossing")]
        self.unexpected_rels = [r for r in self.relationships if r.get("decision") == "Unexpected"]
        self.unreviewed_crossings = [r for r in self.crossing_rels if r.get("decision", "Unknown") == "Unknown"]
        self.bypass_rels = [r for r in self.relationships if "bypass" in (r.get("crossing") or "")]
        self.external_unexpected = [r for r in self.unexpected_rels if "external" in (r.get("crossing") or "")]
        self.other_unexpected = [r for r in self.unexpected_rels if r not in self.external_unexpected and r not in self.bypass_rels]
        self.drafts = self._findings()
        self.register = data.get("findings") or []
        self.findings = self.register if self.register else self.drafts
        self.register_mode = bool(self.register)
        for f in self.findings:
            f.setdefault("ref", f.get("id", ""))
            f.setdefault("kind", "Evidence gap"); f.setdefault("status", "Draft"); f.setdefault("horizon", "")
        self.unvalidated = [f for f in self.findings if f.get("status", "Draft") == "Draft"]
        self.rejected = [f for f in self.findings if f.get("status") == "Rejected"]
        self.reportable = [f for f in self.findings if f.get("status") != "Rejected"]

    def mac(self, value: str) -> str:
        return sanitize_mac(value) if self.sanitize else (value or "").upper()

    def label(self, asset: dict) -> str:
        return asset.get("name") or asset.get("display_type") or asset.get("manufacturer") or self.mac(asset.get("mac", ""))

    def _findings(self) -> list[dict]:
        out: list[dict] = []
        level = self.coverage.get("level")
        if level in ("limited", "none") or (level != "mixed" and "Unconfirmed access port" in self.access_methods):
            out.append({"id": "OBS-01", "title": "Passive visibility is inadequate for inventory completeness", "rating": "High priority", "confidence": "High", "owner": "OT network / site operations",
                        "condition": f"No meaningful third-party unicast traffic was observed ({fmt_int(self.third_party)} frames across {len(self.sessions)} session(s)). Access method recorded: {', '.join(self.access_methods) or 'not recorded'}.",
                        "evidence": f"{fmt_int(self.third_party)} third-party unicast packets; {fmt_int(self.local_unicast)} local unicast; {fmt_int(self.broadcast)} broadcast/multicast; capture duration {fmt_duration_words(self.total_duration)}; no switch configuration or drawing evidence recorded in the tool.",
                        "impact": "Unknown endpoints, communications and dependencies could be omitted from the assessment, creating false assurance if the limitation is not disclosed.",
                        "recommendation": "Develop a collection-point matrix by network leg and obtain approved SPAN/TAP, customer PCAP, switch, firewall, NetFlow, drawing and walkdown evidence as available.",
                        "closure": "Every in-scope network leg has an identified evidence source, a documented time window and a reconciled expected-versus-observed inventory."})
        if self.legs_no_evidence:
            names = ", ".join(f"{l['site']}: {l['name']} ({l.get('status')}, {l.get('evidence_source')})" for l in self.legs_no_evidence[:8])
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Network legs without an evidence source", "rating": "High priority", "confidence": "High", "owner": "Assessment lead / site operations",
                        "condition": f"{len(self.legs_no_evidence)} of {len(self.legs)} recorded network leg(s) have no collected evidence: {names}.",
                        "evidence": "Collection-point matrix maintained in the tool; legs marked Planned, Not accessible or with evidence source 'None yet'.",
                        "impact": "Assets and communications on these legs are absent from the inventory and communication map. Any segmentation conclusion about them is unsupported.",
                        "recommendation": "Obtain an evidence source for each leg (SPAN/TAP, customer PCAP, NetFlow, switch tables or, at minimum, drawings plus interview) or formally record the leg as out of scope with the reason.",
                        "closure": "Every leg has status Collected, Partial with documented limitation, or Out of scope with a recorded reason."})
        if self.undocumented:
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Asset identity and context require drawing and walkdown reconciliation", "rating": "Moderate", "confidence": "High", "owner": "OT engineering / asset owner",
                        "condition": f"{len(self.physical)} likely physical asset(s) and {len(self.derived)} derived identit(ies) were inferred from passive evidence. {len(self.undocumented)} physical asset(s) have no location, criticality, Purdue level, zone, function or owner recorded.",
                        "evidence": f"Assessment context fields empty for: {', '.join(self.label(a) for a in self.undocumented[:8])}{' and others' if len(self.undocumented) > 8 else ''}. {len(self.overrides)} assessor override(s) recorded.",
                        "impact": "Findings cannot be prioritized by operational consequence until each asset's process function, criticality and zone are known.",
                        "recommendation": "Reconcile passive evidence with drawings, equipment lists, controller projects, switch tables, backups, interviews and physical labels. Preserve conflicts as open evidence issues rather than overwriting source claims.",
                        "closure": "Every physical asset carries a validated type, location, function, owner, criticality and zone, or an explicit open-issue record."})
        if self.external:
            top = sorted(self.external, key=lambda r: -int(r.get("packets") or 0))[:5]
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "External communication pathways require policy validation", "rating": "Moderate", "confidence": "Moderate", "owner": "OT security / firewall owner",
                        "condition": f"{len(self.external)} relationship(s) between a local asset and an external or unmapped endpoint were observed.",
                        "evidence": "; ".join(f"{r['endpoint_a']} ↔ {r['endpoint_b']} ({r.get('protocols')}, {fmt_int(r.get('packets'))} pkts)" for r in top),
                        "impact": "Outbound or inbound pathways that are not covered by an approved conduit definition are a common segmentation weakness and a vendor-access blind spot.",
                        "recommendation": "Compare each external relationship with the firewall rule base, approved conduit list and vendor remote-access records. Classify each as approved, tolerated or unexpected.",
                        "closure": "Every external relationship is mapped to an approved conduit or has a remediation owner and date."})
        if self.minority_subnets:
            detail = "; ".join(f"{net}: {', '.join(self.label(a) for a in assets[:5])}" for net, assets in self.minority_subnets.items())
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Multiple IPv4 subnets observed on the same Layer-2 segment", "rating": "Moderate", "confidence": "High", "owner": "OT network owner",
                        "condition": f"Assets from {len(self.subnets)} IPv4 subnets share a broadcast domain. Minority subnet(s): {detail}.",
                        "evidence": "IP evidence (ARP, DHCP, frame source) per Layer-2 identity from the collection point(s) used.",
                        "impact": "A device on an unexpected subnet within an OT segment can indicate a misconfiguration, a guest/overlay network bridged into the segment, a vendor device with factory addressing, or an undocumented path between zones.",
                        "recommendation": "Identify each minority-subnet device, confirm whether its addressing is intentional and documented, and verify no routing or bridging exists between the subnets that bypasses the zone boundary.",
                        "closure": "Each subnet on the segment is documented with purpose and owner, or the stray device is corrected."})
        def _links(rels):
            from .store import Store
            out_links, seen = [], set()
            for r in rels:
                ka, kb = str(r.get("key_a", "")), str(r.get("key_b", ""))
                candidates = [("relationship", Store.relationship_key(ka, kb)), ("pair", Store.pair_key(r.get("level_a", ""), r.get("level_b", "")))]
                candidates += [("asset", k.split(":", 1)[1]) for k in (ka, kb) if k.startswith("asset:")]
                for kind, key in candidates:
                    if key and key != "|" and (kind, key) not in seen:
                        seen.add((kind, key)); out_links.append({"kind": kind, "key": key})
            return out_links
        _rel = lambda r: f"{r['endpoint_a']} ({r.get('level_a', '')}) ↔ {r['endpoint_b']} ({r.get('level_b', '')}): {r.get('protocols')}"
        if self.external_unexpected:
            out.append({"id": f"OBS-{len(out) + 1:02d}", "draft_key": "unexpected-external", "title": "OT assets communicate directly with external or internet endpoints",
                        "rating": "High priority", "confidence": "High", "owner": "OT network owner / firewall owner",
                        "condition": f"{len(self.external_unexpected)} relationship(s) between assets at Purdue Level 3 or below and external/internet endpoints were reviewed by the assessor and marked Unexpected: " + "; ".join(_rel(r) for r in self.external_unexpected[:8]) + ".",
                        "evidence": "Passive flow evidence (external destination, protocol, packet counts) plus the assessor's conduit decision and recorded purpose.",
                        "impact": "A direct path between the control network and the internet exposes OT assets to remote compromise and data exfiltration without an inspected boundary; consumer or vendor devices calling home from a process VLAN are a common cause and are rarely on any drawing.",
                        "recommendation": "Identify the device and destination behind each flow. Remove or relocate devices with no operational reason to reach the internet; route any required external access through the industrial DMZ under explicit firewall rules with logging.",
                        "closure": "No Level ≤3 asset reaches an external endpoint except through a documented, DMZ-terminated conduit.",
                        "links": _links(self.external_unexpected)})
        if self.bypass_rels:
            flagged = [r for r in self.bypass_rels if r.get("decision") == "Unexpected"]
            out.append({"id": f"OBS-{len(out) + 1:02d}", "draft_key": "dmz-bypass", "title": "Direct OT-to-enterprise communications bypass the industrial DMZ", "rating": "High priority",
                        "confidence": "High" if flagged else "Moderate", "owner": "OT network owner",
                        "condition": f"{len(self.bypass_rels)} relationship(s) connect assets at Purdue Level 3 or below directly to Level 4/5 assets with no industrial DMZ in between"
                                     + (f"; {len(flagged)} of them were reviewed by the assessor and marked Unexpected" if flagged else "") + ".",
                        "evidence": "; ".join(_rel(r) + (f" [{r.get('decision')}]" if r.get("decision") and r.get("decision") != "Unknown" else "") for r in self.bypass_rels[:6]),
                        "impact": "Any compromise of an enterprise host has a direct path to control-system assets; ISA/IEC 62443 and NIST SP 800-82 both expect these flows to terminate in a DMZ.",
                        "recommendation": "Confirm the level assignments, then design DMZ-terminated replacements (historian replica, jump host, file transfer broker) for each flow.",
                        "closure": "No Level ≤3 to Level ≥5 relationship remains, or each is documented as approved with compensating controls.",
                        "links": _links(self.bypass_rels)})
        if self.other_unexpected:
            detail = "; ".join(f"{r['endpoint_a']} ↔ {r['endpoint_b']} ({r.get('protocols')}; {r.get('crossing') or 'within level'})" for r in self.other_unexpected[:8])
            out.append({"id": f"OBS-{len(out) + 1:02d}", "draft_key": "unexpected-other", "title": "Communications marked unexpected against the conduit baseline", "rating": "High priority", "confidence": "High", "owner": "OT security / firewall owner",
                        "condition": f"{len(self.other_unexpected)} observed relationship(s) were reviewed by the assessor and marked Unexpected: {detail}.",
                        "evidence": "Passive flow evidence plus assessor conduit decisions recorded in the tool.",
                        "impact": "Unexpected pathways are undocumented attack and failure paths; they typically indicate a missing firewall rule, a bridged network, a vendor connection or a misconfigured host.",
                        "recommendation": "Trace each unexpected relationship to its physical and logical path, decide whether it is required, and either document it as an approved conduit with a control or remove it under change control.",
                        "closure": "No relationship in the register remains marked Unexpected without an owner and remediation date.",
                        "links": _links(self.other_unexpected)})
        if self.unreviewed_crossings and self.zones.get("assigned"):
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Boundary-crossing communications not yet reviewed against a conduit baseline", "rating": "Moderate", "confidence": "High", "owner": "Assessment team / OT engineering",
                        "condition": f"{len(self.unreviewed_crossings)} of {len(self.crossing_rels)} relationship(s) that cross a Purdue level or reach an external endpoint have no conduit decision.",
                        "evidence": "Conduit decisions recorded in the tool; relationships with decision Unknown.",
                        "impact": "The segmentation assessment cannot conclude which crossings are approved until each is classified.",
                        "recommendation": "Review each crossing with the network and OT owners against firewall rules and drawings; mark Approved, Tolerated or Unexpected with the business purpose.",
                        "closure": "Every crossing relationship carries a decision and purpose."})
        if self.zones.get("physical") and self.zones.get("assigned", 0) < self.zones.get("physical", 0) - self.zones.get("infrastructure", 0):
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Purdue level not assigned for all physical assets", "rating": "Low", "confidence": "High", "owner": "Assessment team",
                        "condition": f"{self.zones['assigned']} of {self.zones['physical'] - self.zones.get('infrastructure', 0)} non-infrastructure physical assets have a Purdue level; zone-crossing analysis is incomplete for the rest.",
                        "evidence": "Asset assessment context in the tool.",
                        "impact": "Relationships involving unassigned assets cannot be classified as within-zone or boundary-crossing.",
                        "recommendation": "Assign a level to each physical asset from drawings, function and walkdown evidence.",
                        "closure": "All physical assets carry a Purdue level or are explicitly recorded as out of scope."})
        if self.eol:
            eol_list = ", ".join("%s (%s; %s)" % (self.label(a), a.get("model") or a.get("manufacturer") or "model unknown", a.get("support_status")) for a in self.eol[:8])
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "End-of-life or end-of-support OT assets in service", "rating": "High priority" if any(a.get("criticality") in ("High", "Critical") for a in self.eol) else "Moderate", "confidence": "High", "owner": "OT engineering / asset owner",
                        "condition": f"{len(self.eol)} asset(s) are recorded as end of life or end of support: {eol_list}{' and others' if len(self.eol) > 8 else ''}.",
                        "evidence": "Lifecycle fields recorded from walkdown, drawings or customer inventory; vendor lifecycle notices should be attached to the evidence register.",
                        "impact": "No vendor security fixes; replacement parts and engineering support become scarce; failure or compromise recovery depends on spares and backups.",
                        "recommendation": "Confirm lifecycle status with the vendor, add each unit to the replacement roadmap with a date, and apply compensating controls (segmentation, restricted access, monitored conduits, verified backups) until replaced.",
                        "closure": "Each EOL/EOS asset has a funded replacement date or a documented risk acceptance with compensating controls."})
        if self.no_backup:
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Controller and application backups missing or unverified", "rating": "Moderate", "confidence": "Moderate", "owner": "OT engineering",
                        "condition": f"{len(self.no_backup)} asset(s) have no backup, an unknown backup status, or are rated High/Critical with no backup status recorded: {', '.join(self.label(a) for a in self.no_backup[:8])}{' and others' if len(self.no_backup) > 8 else ''}.",
                        "evidence": "Backup status fields recorded per asset; restore tests not evidenced.",
                        "impact": "Recovery from failure, ransomware or a bad change depends on rebuilding logic and configuration from memory or vendor archives.",
                        "recommendation": "Establish a controller/HMI/historian backup schedule with offline copies and periodic restore tests; record last backup and last successful restore per asset.",
                        "closure": "Every critical asset has a current backup and a documented restore test."})
        if self.cleartext_seen:
            names = ", ".join(f"{IT_SERVICE_PROTOCOLS.get(k, k)} ({fmt_int(v['flows'])} flows)" for k, v in sorted(self.cleartext_seen.items()))
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Cleartext management or file-transfer protocols observed", "rating": "Moderate", "confidence": "Moderate", "owner": "OT engineering / network owner",
                        "condition": f"Protocols that commonly carry credentials or configuration in cleartext were observed: {names}.",
                        "evidence": "Port-based protocol identification from passive flows; payloads were not inspected for credentials.",
                        "impact": "Credentials and device configuration can be captured by anyone with the same network visibility this assessment had.",
                        "recommendation": "Confirm which devices require these services, disable unused services and prefer SSH, HTTPS, SNMPv3 or vendor-secured equivalents where supported.",
                        "closure": "Each cleartext service is either documented as operationally required with compensating controls or disabled."})
        if self.opcua_weak:
            detail = "; ".join(f"{self.label(a)}: {', '.join(issues)}" for a, issues in self.opcua_weak[:8])
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "OPC UA endpoints allow unencrypted or anonymous sessions", "rating": "Moderate", "confidence": "High", "owner": "OT engineering / SCADA owner",
                        "condition": f"{len(self.opcua_weak)} OPC UA endpoint(s) advertise or use a security policy of None and/or anonymous logon: {detail}.",
                        "evidence": "Decoded from OPC UA GetEndpoints/CreateSession/OpenSecureChannel/ActivateSession messages observed passively; the server's own endpoint list is the source for what it offers.",
                        "impact": "With SecurityPolicy None the session is readable and forgeable by anyone with the network position this assessment had; anonymous logon means any such host can browse and, depending on node permissions, write process values.",
                        "recommendation": "Disable the None policy and anonymous token on each server (keep Basic256Sha256 or Aes128_Sha256_RsaOaep with Sign&Encrypt), issue application certificates through a managed trust list, and give collectors and historians named accounts with read-only node permissions.",
                        "closure": "GetEndpoints on each server lists no None policy and no anonymous token; existing clients reconnect with certificates and named users."})
        if self.ot_seen:
            names = ", ".join(f"{OT_PROTOCOLS[k]} ({fmt_int(v['flows'])} flows)" for k, v in sorted(self.ot_seen.items()))
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Industrial protocols observed; conduit approval baseline not yet established", "rating": "Informational", "confidence": "High", "owner": "OT engineering",
                        "condition": f"Industrial control protocols were observed: {names}.",
                        "evidence": "Protocol identification by well-known port and, where present, decoded device-identification payloads.",
                        "impact": "Industrial protocols generally carry no authentication; any host that can reach the controller can typically read or write process values.",
                        "recommendation": "Document each industrial relationship as an approved conduit with its zone pair, direction and purpose; restrict reachability to the documented peers.",
                        "closure": "An approved conduit baseline exists and observed industrial relationships reconcile to it."})
        out.append({"id": "POS-01", "title": "Raw evidence is retained separately from normalized relationships and inferences", "rating": "Positive", "confidence": "High", "owner": "Assessment team",
                    "condition": f"{fmt_int(len(self.flows))} raw flow records, {fmt_int(len(self.relationships))} deduplicated relationships, {fmt_int(len(self.discovery))} discovery-traffic groups and every fingerprint claim are preserved with confidence and evidence.",
                    "evidence": "Assessment export and CSV registers generated by the collector.",
                    "impact": "Conclusions are auditable and can be re-examined without re-collecting.",
                    "recommendation": "Keep the export with the evidence register; do not edit exported evidence files by hand.",
                    "closure": "Not applicable."})
        for f in out:
            f.update(refs_for(f["title"]))
        return out
