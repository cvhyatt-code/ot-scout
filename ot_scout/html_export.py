"""A single, self-contained HTML export of the assessment.

One file, inline CSS, no scripts and nothing fetched from anywhere: the inventory, the communication
relationships and the findings register, with a line saying what generated it. It opens in any
browser, offline, and can be attached to an email or printed to PDF from there.
"""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape

CSS = """
body{margin:0;background:#fff;color:#16212b;font:13px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1200px;margin:0 auto;padding:28px 24px 40px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px;padding-bottom:4px;border-bottom:2px solid #d9e1e7}
.sub{color:#617181;font-size:12px}
.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0}
.tile{border:1px solid #d9e1e7;border-radius:6px;padding:8px 12px;min-width:120px}
.tile strong{display:block;font-size:20px}
table{border-collapse:collapse;width:100%;margin-top:6px}
th,td{border:1px solid #d9e1e7;padding:5px 7px;text-align:left;vertical-align:top}
th{background:#f3f6f8;font-size:12px}
td .sub{display:block}
.empty{color:#617181;font-style:italic}
@media print{main{padding:0}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def _e(value) -> str:
    return escape(str(value if value is not None else ""))


def _table(header: list[str], rows: list[list[str]], empty: str) -> str:
    if not rows:
        return f'<p class="empty">{_e(empty)}</p>'
    head = "".join(f"<th>{_e(h)}</th>" for h in header)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _cell(main, sub="") -> str:
    return _e(main) + (f'<span class="sub">{_e(sub)}</span>' if sub else "")


def build_html(store, product: str, version: str, now: datetime | None = None) -> str:
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")
    summary = store.dashboard()
    assets = [a for a in store.assets() if a.get("physical_asset")]
    relationships = store.relationships(100000)
    findings = [f for f in store.findings() if f.get("status") != "Rejected"]
    sessions = store.sessions()
    names = sorted({s.get("assessment", "") for s in sessions if s.get("assessment")})
    title = ", ".join(names) or "Assessment"

    asset_rows = [[_cell(a.get("name") or "Unnamed", a.get("ips") or ""),
                   _cell(a.get("mac") or ""),
                   _cell(a.get("manufacturer") or "", " ".join(x for x in (a.get("model"), a.get("firmware")) if x)),
                   _cell(a.get("display_type") or ""),
                   _cell(a.get("purdue_level") or "Unassigned"),
                   _cell(a.get("classification") or "", a.get("source") or ""),
                   _cell(a.get("observed_protocols") or "")] for a in assets]
    rel_rows = [[_cell(r.get("endpoint_a"), r.get("level_a") or ""),
                 _cell(r.get("endpoint_b"), r.get("level_b") or ""),
                 _cell(r.get("category") or "", r.get("crossing") or ""),
                 _cell(r.get("protocols") or ""),
                 _cell(r.get("decision") or "Unknown", r.get("purpose") or ""),
                 _cell(f"{int(r.get('packets') or 0):,}")] for r in relationships]
    finding_rows = [[_cell(f.get("ref")),
                     _cell(f.get("title"), f.get("condition") or ""),
                     _cell(f.get("rating")), _cell(f.get("confidence")), _cell(f.get("status")),
                     _cell(f.get("recommendation") or ""),
                     _cell("; ".join(x for x in (f.get("iec62443"), f.get("attack")) if x))] for f in findings]

    tiles = "".join(f'<div class="tile"><strong>{int(summary.get(k) or 0):,}</strong>{_e(label)}</div>' for k, label in (
        ("assets", "physical assets"), ("identities", "observed identities"), ("relationships", "relationships"),
        ("sessions", "collection sessions"), ("packets", "packets observed")))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)} — {_e(product)} export</title><style>{CSS}</style></head><body><main>
<h1>{_e(title)}</h1>
<div class="sub">Generated {_e(stamp)} by {_e(product)} v{_e(version)}. Passive observations are evidence, not proof of complete coverage.</div>
<div class="tiles">{tiles}<div class="tile"><strong>{len(findings)}</strong>findings</div></div>
<h2>Asset inventory ({len(assets)})</h2>
{_table(["Asset", "MAC", "Manufacturer / model", "Device type", "Purdue level", "Classification", "Protocols"], asset_rows, "No physical assets recorded.")}
<h2>Communication relationships ({len(relationships)})</h2>
{_table(["Endpoint A", "Endpoint B", "Category", "Protocols", "Conduit decision", "Packets"], rel_rows, "No relationships recorded.")}
<h2>Findings ({len(findings)})</h2>
{_table(["Ref", "Finding", "Rating", "Confidence", "Status", "Recommendation", "References"], finding_rows, "No findings recorded.")}
</main></body></html>
"""
