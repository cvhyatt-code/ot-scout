from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import sys
import tempfile
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .capture import interfaces
from .frameworks import catalogue
from .report import Analysis, build_report, collect
from .store import Store


STATIC = Path(__file__).parent / "static"
ROOT = Path(__file__).resolve().parent.parent
MAX_UPLOAD = 512 * 1024 * 1024

DOCS = {"changelog": ("CHANGELOG.md", "No changelog shipped with this build."),
        "guide": ("ASSESSMENT_GUIDE.md", "No assessment guide shipped with this build.")}


def read_doc(name: str) -> str:
    filename, fallback = DOCS[name]
    for base in (ROOT, STATIC):
        target = base / filename
        if target.is_file():
            return target.read_text(encoding="utf-8")
    return fallback


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, store, capture):
        super().__init__(address, handler)
        self.store = store
        self.capture = capture
        self.quiet_status = True
        self.main_database = store.path
        self.demo_database = str(Path(store.path).parent / "demo.db")

    def switch_database(self, target: str) -> dict:
        if self.capture.running:
            raise ValueError("Stop capture before switching data sets")
        if target == "demo":
            path = self.demo_database
            demo_script = Path(__file__).resolve().parent.parent / "demo.py"
            stale = Path(path).exists() and demo_script.exists() and demo_script.stat().st_mtime > Path(path).stat().st_mtime
            if not Path(path).exists() or stale:
                # the demo database is derived from demo.py — rebuild it whenever the script is newer (a new build shipped)
                self.build_demo()
            new_store = Store(path)
        elif target == "demo-rebuild":
            self.build_demo()
            new_store = Store(self.demo_database)
        elif target == "main":
            new_store = Store(self.main_database)
        else:
            raise ValueError("Unknown data set")
        new_store.vendors = self.store.vendors  # keep the loaded OUI table
        self.store = new_store
        self.capture.store = new_store
        return self.database_status()

    def build_demo(self):
        import importlib
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        demo = importlib.import_module("demo")
        demo.build_demo(Path(self.demo_database))

    def database_status(self) -> dict:
        current = "demo" if Path(self.store.path).resolve() == Path(self.demo_database).resolve() else "main"
        return {"current": current, "path": self.store.path, "demo_exists": Path(self.demo_database).exists(),
                "label": "DEMO DATA (fictitious Riverbend Regional Water Utility)" if current == "demo" else "Live assessment data"}


class Handler(BaseHTTPRequestHandler):
    server_version = f"OTScout/{__version__}"

    def log_message(self, fmt, *args):
        if "/api/status" in (fmt % args) and self.server.quiet_status:
            return
        print(f"{self.address_string()} - {fmt % args}")

    def _json(self, payload, status=200):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(raw)

    def _body(self, max_size=1_000_000):
        size = int(self.headers.get("Content-Length", "0"))
        if size < 0 or size > max_size:
            raise ValueError("Request is too large")
        return self.rfile.read(size)

    def _json_body(self):
        return json.loads(self._body().decode("utf-8") or "{}")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/status":
            store = self.server.store
            return self._json({**self.server.capture.status(), **store.dashboard(), "coverage": store.coverage(), "generation": store.generation, "dataset": self.server.database_status()["current"]})
        if path == "/api/interfaces": return self._json(interfaces())
        if path == "/api/about":
            return self._json({"version": __version__, "changelog": read_doc("changelog"), "guide": read_doc("guide")})
        if path == "/api/database": return self._json(self.server.database_status())
        if path == "/api/vendor-status": return self._json(self.server.store.vendor_status())
        if path == "/api/assets": return self._json(self.server.store.assets_with_exposure())
        if path == "/api/summary":
            from .exposure import fleet_view, iec62443_rollup
            store = self.server.store
            assets = store.assets_with_exposure()
            top = sorted([a for a in assets if a.get("physical_asset")], key=lambda a: (-int(a.get("exposure") or 0), a.get("name") or ""))[:15]
            findings = [f for f in store.findings() if f.get("status") != "Rejected"]
            return self._json({"top_exposure": [{k: a.get(k) for k in ("id", "name", "mac", "manufacturer", "model", "display_type", "criticality", "purdue_level", "exposure", "exposure_band", "exposure_factors")} for a in top],
                               "fleet": fleet_view(assets), "iec62443": iec62443_rollup(findings)})
        if path == "/api/relationships": return self._json(self.server.store.relationships())
        if path == "/api/discovery": return self._json(self.server.store.discovery_traffic())
        if path == "/api/connections": return self._json(self.server.store.connections())
        if path == "/api/sessions": return self._json(self.server.store.sessions())
        if path == "/api/template/assets.csv": return self._download("ot-scout-asset-template.csv", self.server.store.asset_template_csv(), "text/csv")
        if path == "/api/asset-options":
            store = self.server.store
            return self._json({"sources": store.ASSET_SOURCES, "support_statuses": store.SUPPORT_STATUSES, "backup_statuses": store.BACKUP_STATUSES, "levels": store.PURDUE_LEVELS})
        if path == "/api/zones":
            store = self.server.store
            return self._json({**store.zone_summary(), "levels_list": store.PURDUE_LEVELS, "decisions_list": store.CONDUIT_DECISIONS})
        if path == "/api/export/purdue.svg":
            return self._download("purdue-zones.svg", self.server.store.purdue_svg().encode("utf-8"), "image/svg+xml")
        if path == "/api/findings":
            store = self.server.store
            return self._json({"findings": store.findings(), "kinds": store.FINDING_KINDS, "ratings": store.FINDING_RATINGS,
                               "confidence": store.FINDING_CONFIDENCE, "horizons": store.FINDING_HORIZONS, "statuses": store.FINDING_STATUSES,
                               "frameworks": catalogue()})
        if path == "/api/findings/drafts":
            return self._json(Analysis(collect(self.server.store), False).drafts)
        if path == "/api/sites":
            store = self.server.store
            return self._json({"sites": store.sites(), "checklist_items": [{"item": k, "label": l, "description": d} for k, l, d in store.CHECKLIST_ITEMS],
                               "checklist_statuses": store.CHECKLIST_STATUSES, "evidence_sources": store.LEG_EVIDENCE_SOURCES,
                               "leg_statuses": store.LEG_STATUSES, "collection_points": store.known_collection_points()})
        if path == "/api/export/assets.csv": return self._download("assets.csv", self.server.store.csv_export("assets"), "text/csv")
        if path == "/api/export/relationships.csv": return self._download("relationships.csv", self.server.store.csv_export("relationships"), "text/csv")
        if path == "/api/export/discovery.csv": return self._download("discovery-traffic.csv", self.server.store.csv_export("discovery"), "text/csv")
        if path == "/api/export/connections.csv": return self._download("flows.csv", self.server.store.csv_export("flows"), "text/csv")
        if path == "/api/export/assessment.json": return self._download("assessment.json", self.server.store.json_export(), "application/json")
        if path == "/api/export/report.docx":
            query = {k: v[0].strip() for k, v in parse_qs(urlparse(self.path).query).items()}
            meta = {"prepared_for": query.get("prepared_for", ""), "prepared_by": query.get("prepared_by", ""),
                    "title": query.get("title", ""), "banner": query.get("banner", ""), "sanitize": query.get("sanitize") in ("1", "true", "on")}
            raw = build_report(collect(self.server.store), meta)
            return self._download("ot-scout-assessment-report.docx", raw, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        if path == "/api/export/evidence.zip":
            query = {k: v[0].strip() for k, v in parse_qs(urlparse(self.path).query).items()}
            meta = {"prepared_for": query.get("prepared_for", ""), "prepared_by": query.get("prepared_by", ""),
                    "title": query.get("title", ""), "banner": query.get("banner", ""), "sanitize": query.get("sanitize") in ("1", "true", "on")}
            return self._download_file(self.build_evidence_package(meta), "ot-scout-evidence-package.zip", "application/zip", delete=True)
        if path == "/": path = "/index.html"
        target = (STATIC / path.lstrip("/")).resolve()
        if STATIC.resolve() not in target.parents or not target.is_file():
            return self.send_error(404)
        raw = target.read_bytes()
        if target.name == "index.html":
            raw = raw.replace(b"{{VERSION}}", __version__.encode())
        self.send_response(200); self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def build_evidence_package(self, meta: dict) -> str:
        """Everything a client or a reviewer needs to check the work, with a SHA-256 manifest: the assessment
        JSON, the report, every CSV/SVG export and the raw PCAP of every live session in this data set."""
        store = self.server.store
        stamp = __import__("time").strftime("%Y-%m-%d %H:%M:%S %Z")
        fd, tmp_path = tempfile.mkstemp(suffix=".zip"); os.close(fd)
        entries = []  # (name in zip, sha256, size, note)

        def add_bytes(zf, name, raw, note):
            zf.writestr(name, raw)
            entries.append((name, hashlib.sha256(raw).hexdigest(), len(raw), note))

        def add_file(zf, name, source, note):
            h = hashlib.sha256(); size = 0
            with open(source, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk); size += len(chunk)
            zf.write(source, name)
            entries.append((name, h.hexdigest(), size, note))

        with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zf:
            add_bytes(zf, "assessment.json", store.json_export(), "Full evidence export (sessions, assets, relationships, sites, findings, zones)")
            add_bytes(zf, "report.docx", build_report(collect(store), meta), "Assessment report rendered from assessment.json at packaging time")
            for kind, name in (("assets", "assets.csv"), ("relationships", "relationships.csv"), ("discovery", "discovery-traffic.csv"), ("flows", "flows.csv")):
                add_bytes(zf, name, store.csv_export(kind), "CSV register")
            add_bytes(zf, "purdue-zones.svg", store.purdue_svg().encode("utf-8"), "Purdue zone and conduit diagram")
            sessions = store.sessions()
            for sess in sessions:
                pcap = sess.get("pcap_path") or ""
                if pcap and Path(pcap).is_file():
                    add_file(zf, f"captures/{Path(pcap).name}", pcap, f"Raw capture, session {sess['id']} — {sess['collection_point']} ({sess['interface']}); {sess.get('frames') or sess['packets']} frames, {sess.get('dropped', 0)} dropped by kernel")
            lines = [f"OT Scout evidence package — generated {stamp} by OT Scout v{__version__}",
                     f"Data set: {self.server.database_status()['label']}",
                     "", "Verify after extracting with:  sha256sum -c SHA256SUMS", "",
                     "Sessions:"]
            for sess in sessions:
                lines.append(f"  #{sess['id']} {sess['started_at']} → {sess['ended_at'] or 'running'}  {sess['assessment']} / {sess['site']} / {sess['collection_point']}  "
                             f"{sess['source_type']} {sess['interface']}  {sess['access_method']}  frames={sess.get('frames') or sess['packets']} recorded={sess['packets']} dropped={sess.get('dropped', 0)}"
                             + (f"  pcap={Path(sess['pcap_path']).name}" if sess.get('pcap_path') else "  pcap=not saved"))
            lines += ["", "Files:"]
            for name, digest, size, note in entries:
                lines.append(f"  {name}  {size:,} bytes  — {note}")
            lines += ["", "SHA-256:"]
            for name, digest, size, note in entries:
                lines.append(f"  {digest}  {name}")
            zf.writestr("MANIFEST.txt", "\n".join(lines) + "\n")
            zf.writestr("SHA256SUMS", "".join(f"{digest}  {name}\n" for name, digest, size, note in entries))
        return tmp_path

    def _download_file(self, source: str, name: str, content_type: str, delete: bool = False):
        size = os.path.getsize(source)
        self.send_response(200); self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{name}"')
        self.send_header("Content-Length", str(size)); self.end_headers()
        try:
            with open(source, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    self.wfile.write(chunk)
        finally:
            if delete:
                try: os.unlink(source)
                except OSError: pass

    def _download(self, name, raw, content_type):
        self.send_response(200); self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{name}"')
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/start":
                data = self._json_body()
                required = ["assessment", "site", "collection_point", "interface", "access_method"]
                if any(not str(data.get(k, "")).strip() for k in required):
                    raise ValueError("Assessment, site, collection point and interface are required")
                try:
                    rate_limit = int(data.get("rate_limit") or 0) or None
                except (TypeError, ValueError):
                    rate_limit = None
                session = self.server.capture.start(*(str(data[k]).strip() for k in required), rate_limit=rate_limit,
                                                    save_pcap=bool(data.get("save_pcap", True)))
                return self._json({"ok": True, "session_id": session})
            if path == "/api/database/switch":
                return self._json({"ok": True, **self.server.switch_database(str(self._json_body().get("target", "")))})
            if path == "/api/stop":
                self.server.capture.stop(); return self._json({"ok": True})
            if path == "/api/reset":
                if self.server.capture.running: raise ValueError("Stop capture before resetting")
                self.server.store.reset(); return self._json({"ok": True})
            if path == "/api/update-vendors":
                if self.server.capture.running: raise ValueError("Stop capture before updating the vendor database")
                count = self.server.store.update_vendors()
                return self._json({"ok": True, "entries": count})
            if path == "/api/zones/accept-suggestions":
                body = self._json_body()
                count = self.server.store.accept_suggested_levels(int(body.get("min_confidence", 50)), bool(body.get("overwrite")))
                return self._json({"ok": True, "applied": count})
            if path == "/api/conduits":
                body = self._json_body()
                return self._json({"ok": True, "conduit": self.server.store.save_conduit(body.get("key_a", ""), body.get("key_b", ""), body)})
            if path == "/api/findings":
                return self._json({"ok": True, "finding": self.server.store.save_finding(self._json_body())})
            if path == "/api/findings/import-drafts":
                drafts = Analysis(collect(self.server.store), False).drafts
                return self._json({"ok": True, "added": self.server.store.import_draft_findings(drafts)})
            if path.startswith("/api/findings/"):
                parts = path.strip("/").split("/")
                if len(parts) != 4 or not parts[2].isdigit() or parts[3] != "delete":
                    raise ValueError("Invalid finding request")
                self.server.store.delete_finding(int(parts[2])); return self._json({"ok": True})
            if path == "/api/sites":
                return self._json({"ok": True, "site": self.server.store.save_site(self._json_body())})
            if path.startswith("/api/sites/"):
                parts = path.strip("/").split("/")
                if len(parts) < 3 or not parts[2].isdigit():
                    raise ValueError("Invalid site identifier")
                site_id, action = int(parts[2]), parts[3] if len(parts) > 3 else ""
                if action == "delete":
                    self.server.store.delete_site(site_id); return self._json({"ok": True})
                if action == "checklist":
                    body = self._json_body()
                    return self._json({"ok": True, "site": self.server.store.save_checklist_item(site_id, str(body.get("item", "")), body)})
                if action == "legs":
                    return self._json({"ok": True, "site": self.server.store.save_leg(site_id, self._json_body())})
                raise ValueError("Unknown site action")
            if path.startswith("/api/legs/"):
                parts = path.strip("/").split("/")
                if len(parts) != 4 or not parts[2].isdigit() or parts[3] != "delete":
                    raise ValueError("Invalid network leg request")
                self.server.store.delete_leg(int(parts[2])); return self._json({"ok": True})
            if path == "/api/assets/new":
                return self._json({"ok": True, "asset": self.server.store.add_documented_asset(self._json_body())})
            if path == "/api/import-assets":
                raw = self._body(20 * 1024 * 1024)
                result = self.server.store.import_assets_csv(raw, self.headers.get("X-Source", "").strip() or "Spreadsheet import")
                return self._json({"ok": True, **result})
            if path.startswith("/api/assets/"):
                parts = path.strip("/").split("/")
                if len(parts) < 3 or not parts[2].isdigit():
                    raise ValueError("Invalid asset identifier")
                asset_id, action = int(parts[2]), parts[3] if len(parts) > 3 else ""
                if action == "merge":
                    body = self._json_body()
                    return self._json({"ok": True, "asset": self.server.store.merge_assets(asset_id, int(body.get("secondary", 0)), str(body.get("note", "")))})
                if action == "delete":
                    self.server.store.delete_asset(asset_id); return self._json({"ok": True})
                if action:
                    raise ValueError("Unknown asset action")
                item = self.server.store.update_asset(asset_id, self._json_body())
                return self._json({"ok": True, "asset": item})
            if path == "/api/import-pcap":
                data = self._body(MAX_UPLOAD)
                meta = {k: self.headers.get(h, "").strip() for k, h in {
                    "assessment":"X-Assessment", "site":"X-Site", "point":"X-Collection-Point", "filename":"X-Filename"}.items()}
                if any(not v for v in meta.values()): raise ValueError("PCAP import metadata is incomplete")
                try:
                    rate_limit = int(self.headers.get("X-Rate-Limit", "") or 0) or None
                except ValueError:
                    rate_limit = None
                result = self.server.capture.import_pcap(data, meta["assessment"], meta["site"], meta["point"], meta["filename"], rate_limit=rate_limit)
                return self._json({"ok": True, **result})
            self.send_error(404)
        except (ValueError, RuntimeError, json.JSONDecodeError) as exc:
            self._json({"ok": False, "error": str(exc)}, 400)
        except Exception as exc:
            self._json({"ok": False, "error": f"Unexpected error: {exc}"}, 500)
