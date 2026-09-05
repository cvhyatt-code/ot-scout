"""Per-asset exposure score: a transparent prioritisation aid, not a probability.

Adds points for evidence the tool already holds — how critical the assessor said the asset is, what
it talks to across zone boundaries and how those conduits were judged, lifecycle and backup state,
cleartext management services it serves, and OPC UA security posture. Every point carries a reason
so the report can print "why 78" next to the number. Capped at 100 and banded.

Deliberately not a vulnerability score: no CVE feed, no exploit likelihood. It answers the plant
manager's question — "which box do I fix first" — from what was observed and documented on site.
"""
from __future__ import annotations

CRITICALITY_BASE = {"Critical": 40, "High": 30, "Moderate": 20, "Low": 10}
UNSET_CRITICALITY = 15
CLEARTEXT_MANAGEMENT = {"TELNET", "FTP", "HTTP", "SNMP", "VNC", "TFTP"}
BANDS = ((70, "Critical"), (45, "High"), (25, "Moderate"), (0, "Low"))


def band(score: int) -> str:
    for floor, name in BANDS:
        if score >= floor:
            return name
    return "Low"


FINDING_POINTS = {"Critical": 20, "High priority": 12, "Moderate": 6, "Low": 2}


def _findings_naming(asset: dict, findings: list[dict]) -> list[dict]:
    """Findings whose 'assets' field names this asset (by name or MAC), excluding rejected and positive ones."""
    needles = [v.lower() for v in (asset.get("name"), asset.get("mac")) if v and len(v) >= 4]
    if not needles:
        return []
    out = []
    for f in findings:
        if f.get("status") == "Rejected" or f.get("rating") in ("Positive", "Informational"):
            continue
        blob = (f.get("assets") or "").lower()
        if blob and any(n in blob for n in needles):
            out.append(f)
    return out


def score_asset(asset: dict, relationships: list[dict], served_ports: set[int] | None = None, findings: list[dict] | None = None) -> dict:
    """relationships: the deduplicated relationships this asset takes part in (either endpoint)."""
    factors: list[tuple[str, int]] = []
    crit = asset.get("criticality") or ""
    if crit in CRITICALITY_BASE:
        factors.append((f"Criticality {crit}", CRITICALITY_BASE[crit]))
    else:
        factors.append(("Criticality not recorded (treated as moderate-unknown)", UNSET_CRITICALITY))

    ext = [r for r in relationships if "External" in (r.get("level_a"), r.get("level_b"))]
    bypass = [r for r in relationships if "bypass" in (r.get("crossing") or "")]
    unexpected = [r for r in relationships if r.get("decision") == "Unexpected"]
    unreviewed = [r for r in relationships if r.get("crossing") and r.get("decision", "Unknown") == "Unknown"]

    if ext:
        worst = "Unexpected" if any(r.get("decision") == "Unexpected" for r in ext) else "Unknown" if any(r.get("decision", "Unknown") == "Unknown" for r in ext) else "Tolerated" if any(r.get("decision") == "Tolerated" for r in ext) else "Approved"
        pts = {"Unexpected": 25, "Unknown": 15, "Tolerated": 12, "Approved": 5}[worst]
        factors.append((f"Talks to an external endpoint ({len(ext)} relationship(s), worst decision {worst})", pts))
    if bypass:
        worst = "Unexpected" if any(r.get("decision") == "Unexpected" for r in bypass) else "Unknown" if any(r.get("decision", "Unknown") == "Unknown" for r in bypass) else "Tolerated" if any(r.get("decision") == "Tolerated" for r in bypass) else "Approved"
        pts = {"Unexpected": 20, "Unknown": 15, "Tolerated": 10, "Approved": 5}[worst]
        factors.append((f"OT-to-enterprise path bypassing the industrial DMZ ({len(bypass)}, worst decision {worst})", pts))
    other_unexpected = [r for r in unexpected if r not in ext and r not in bypass]
    if other_unexpected:
        factors.append((f"Relationship(s) marked Unexpected ({len(other_unexpected)})", 15))
    other_unreviewed = [r for r in unreviewed if r not in ext and r not in bypass]
    if other_unreviewed:
        factors.append((f"Boundary crossing(s) not yet reviewed ({len(other_unreviewed)})", 5))

    support = asset.get("support_status") or ""
    if support.startswith("End"):
        factors.append((f"Lifecycle: {support}", 15))
    elif support in ("Extended support", "Unknown"):
        factors.append((f"Lifecycle: {support}", 5))
    backup = asset.get("backup_status") or ""
    if backup == "No backup":
        factors.append(("No backup", 10))
    elif backup in ("Unknown", "Backed up, untested") or (not backup and crit in ("High", "Critical")):
        factors.append((f"Backup {backup.lower() if backup else 'status not recorded'}", 5))

    served = {p for p in (served_ports or set())}
    cleartext = sorted({name for port, name in ((23, "Telnet"), (21, "FTP"), (80, "HTTP"), (161, "SNMP"), (5900, "VNC"), (69, "TFTP")) if port in served})
    if cleartext:
        factors.append((f"Serves cleartext management: {', '.join(cleartext)}", 8))

    fps = {(f.get("field"), f.get("value") or "") for f in (asset.get("fingerprints") or [])}
    weak_ua = [v for k, v in fps if (k == "opcua_security_policies" and "None" in v.split(", ")) or (k == "opcua_user_tokens" and "Anonymous" in v)]
    if weak_ua:
        factors.append(("OPC UA server offers SecurityPolicy None and/or anonymous logon", 10))
    elif any(k == "opcua_auth" and v == "Anonymous" for k, v in fps) or any(k == "opcua_security_policy" and v == "None" for k, v in fps):
        factors.append(("OPC UA client uses an unencrypted channel and/or anonymous logon", 8))

    if not asset.get("purdue_level") and asset.get("physical_asset") and not any(k in (asset.get("display_type") or "").lower() for k in ("network infrastructure", "gateway", "router", "switch", "access point")):
        factors.append(("No Purdue level assigned — zone analysis incomplete for this asset", 5))

    named = _findings_naming(asset, findings or [])
    if named:
        worst = min(named, key=lambda f: list(FINDING_POINTS).index(f.get("rating")) if f.get("rating") in FINDING_POINTS else 99)
        pts = FINDING_POINTS.get(worst.get("rating"), 2) + 3 * (len(named) - 1)
        factors.append((f"Named in {len(named)} finding(s) in the register, worst {worst.get('rating')} ({worst.get('ref') or worst.get('id') or ''})", pts))

    total = min(100, sum(p for _, p in factors))
    return {"exposure": total, "exposure_band": band(total), "exposure_factors": [f"{why} (+{pts})" for why, pts in factors]}


def annotate(assets: list[dict], relationships: list[dict], served_index: dict[int, set[int]] | None = None, findings: list[dict] | None = None) -> None:
    """Attach exposure fields to every physical asset in place. relationships carry key_a/key_b as 'asset:<id>'."""
    by_asset: dict[int, list[dict]] = {}
    for r in relationships:
        for key in (r.get("key_a", ""), r.get("key_b", "")):
            if str(key).startswith("asset:"):
                by_asset.setdefault(int(str(key)[6:]), []).append(r)
    for a in assets:
        if not a.get("physical_asset"):
            a["exposure"], a["exposure_band"], a["exposure_factors"] = 0, "", []
            continue
        a.update(score_asset(a, by_asset.get(a.get("id"), []), (served_index or {}).get(a.get("id"), set()), findings))


def fleet_view(assets: list[dict]) -> list[dict]:
    """Physical assets grouped by manufacturer + model: count, firmware spread, lifecycle and exposure."""
    groups: dict[tuple[str, str], dict] = {}
    for a in assets:
        if not a.get("physical_asset"):
            continue
        key = ((a.get("manufacturer") or "Unknown manufacturer").strip(), (a.get("model") or a.get("display_type") or "Unknown model").strip())
        g = groups.setdefault(key, {"manufacturer": key[0], "model": key[1], "count": 0, "firmware": set(), "eol": 0, "no_backup": 0, "max_exposure": 0, "names": []})
        g["count"] += 1
        if a.get("firmware"):
            g["firmware"].add(a["firmware"])
        if (a.get("support_status") or "").startswith("End"):
            g["eol"] += 1
        if a.get("backup_status") in ("No backup", "Unknown"):
            g["no_backup"] += 1
        g["max_exposure"] = max(g["max_exposure"], int(a.get("exposure") or 0))
        g["names"].append(a.get("name") or a.get("display_type") or "unnamed")
    out = []
    for g in groups.values():
        g["firmware"] = ", ".join(sorted(g["firmware"])) or "—"
        out.append(g)
    return sorted(out, key=lambda g: (-g["count"], -g["max_exposure"], g["manufacturer"], g["model"]))


def iec62443_rollup(findings: list[dict]) -> list[dict]:
    """Which IEC 62443 requirements the findings bear on, with the finding refs, most-cited first."""
    hits: dict[str, dict] = {}
    for f in findings:
        for ref in (f.get("iec62443") or "").split(";"):
            ref = ref.strip()
            if not ref:
                continue
            ident = ref.split(" ", 2)
            key = " ".join(ident[:2]) if ident[0] in ("SR", "2-4") and len(ident) > 1 else ref
            name = ref[len(key):].strip()
            h = hits.setdefault(key, {"requirement": key, "name": name, "findings": [], "worst": ""})
            h["findings"].append(f.get("ref") or f.get("id") or "")
            order = ["Critical", "High priority", "Moderate", "Low", "Informational", "Positive"]
            if not h["worst"] or order.index(f.get("rating", "Informational")) < order.index(h["worst"]):
                h["worst"] = f.get("rating", "")
    return sorted(hits.values(), key=lambda h: (-len(h["findings"]), h["requirement"]))
