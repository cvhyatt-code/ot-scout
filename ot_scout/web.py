from __future__ import annotations

import json
import mimetypes
import os
import re
import sys
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from . import edition as default_edition
from .analysis import Analysis, collect
from .bind import TOKEN_HEADER, allowed_hosts, bare_host, cookie_name, host_header_ok, new_token, origin_ok, token_ok
from .capture import interfaces
from .frameworks import catalogue
from .html_export import build_html
from .paths import hand_back

STATIC = Path(__file__).parent / "static"
ROOT = Path(__file__).resolve().parent.parent
MAX_UPLOAD = 512 * 1024 * 1024

DOCS = {"changelog": ("CHANGELOG.md", "No changelog shipped with this build."),
        "guide": ("ASSESSMENT_GUIDE.md", "")}

# The tabs every edition has, in order. Modules add theirs after the tab they name.
CORE_TABS = (("collect", "Collect"), ("inventory", "Inventory"), ("comms", "Communications"),
             ("zones", "Zones"), ("findings", "Findings"), ("report", "Report"))

SLOT = re.compile(r"<!--\s*slot:([a-z0-9-]+)\s*-->")


def read_doc(name: str) -> str:
    filename, fallback = DOCS[name]
    for base in (ROOT, STATIC):
        target = base / filename
        if target.is_file():
            return target.read_text(encoding="utf-8")
    return fallback


def slug(text: str) -> str:
    return "-".join(p for p in re.sub(r"[^a-z0-9]+", "-", text.lower()).split("-") if p) or "scout"


def render_page(edition, extensions, token: str) -> bytes:
    """The single-page UI: the core page with each module's tabs, fragments and script slotted in."""
    page = (STATIC / "index.html").read_text(encoding="utf-8")
    labels = getattr(edition, "TAB_LABELS", {}) or {}
    tabs = [(tab_id, labels.get(tab_id, label)) for tab_id, label in CORE_TABS]
    for extension in extensions:
        for tab_id, label, after in extension.tabs:
            ids = [t[0] for t in tabs]
            tabs.insert(ids.index(after) + 1 if after in ids else len(tabs), (tab_id, label))
    buttons = []
    for i, (tab_id, label) in enumerate(tabs):
        active = ' class="active"' if i == 0 else ""
        buttons.append(f'<button data-tab="{tab_id}"{active}>{label}</button>')
    slots: dict[str, list[str]] = {"tabs": ["".join(buttons)]}
    scripts = []
    for extension in extensions:
        for slot, html in extension.fragments().items():
            slots.setdefault(slot, []).append(html)
        if extension.script():
            scripts.append(f"// ---- {extension.name} ----\n{extension.script()}")
    page = SLOT.sub(lambda m: "\n".join(slots.get(m.group(1), [])), page)
    page = page.replace("/*slot:script*/", "\n".join(scripts))
    theme = f'<link rel="stylesheet" href="/theme-{edition.THEME}.css">' if getattr(edition, "THEME", "") else ""
    guide = ('<a href="#" id="guideLink" title="Step-by-step plan for running an assessment with this tool">Guide</a>'
             if read_doc("guide") else "")
    values = {"PRODUCT": edition.NAME, "TAGLINE": edition.TAGLINE, "THEME": theme, "GUIDE_LINK": guide,
              "FOOTER": edition.FOOTER.format(name=edition.NAME, version=__version__),
              "ABOUT_NOTICE": edition.ABOUT_NOTICE.format(name=edition.NAME, version=__version__),
              "VERSION": __version__, "TOKEN": token}
    for key, value in values.items():
        page = page.replace("{{" + key + "}}", value)
    return page.encode("utf-8")


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, store, capture, allowed=None, token=None, extensions=(), edition=None,
                 data_dir=None):
        super().__init__(address, handler)
        self.store = store
        self.capture = capture
        self.allowed_hosts = allowed_hosts(address[0], allowed)
        self.token = token or new_token()
        self.cookie = cookie_name(self.server_address[1])
        self.edition = edition or default_edition
        self.extensions = list(extensions)
        self.quiet_status = True
        self._data_dir = Path(data_dir).resolve() if data_dir else Path(store.path).resolve().parent
        self.main_database = str(self._data_dir / "assessment.db") if data_dir else store.path
        self.demo_database = str(self._data_dir / "demo.db")
        self._page = None
        store.ensure_schema()       # a module loaded after this store was opened still gets its tables
        for extension in self.extensions:
            extension.attach(self)

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    def page(self) -> bytes:
        if self._page is None:
            self._page = render_page(self.edition, self.extensions, self.token)
        return self._page

    def _adopt(self, store) -> None:
        store.vendors = self.store.vendors      # keep the loaded OUI table
        store.ensure_schema()
        self.store = store
        self.capture.store = store

    def build_demo(self):
        import importlib
        sys.path.insert(0, str(ROOT))
        demo = importlib.import_module("demo")
        demo.build_demo(Path(self.demo_database))
        hand_back(self.data_dir)

    def ensure_demo(self):
        """Build the demonstration database if it is missing, or older than the demo.py that builds it."""
        path, script = Path(self.demo_database), ROOT / "demo.py"
        stale = path.exists() and script.exists() and script.stat().st_mtime > path.stat().st_mtime
        if not path.exists() or stale:
            self.build_demo()

    def database_status(self) -> dict:
        current = "demo" if Path(self.store.path).resolve() == Path(self.demo_database).resolve() else "main"
        return {"current": current, "path": self.store.path, "file": Path(self.store.path).name,
                "engagement": "" if current == "demo" else self.store.engagement_name(),
                "demo_exists": Path(self.demo_database).exists(),
                "label": "DEMO DATA (fictitious Riverbend Regional Water Utility)" if current == "demo" else "Live assessment data"}

    def assets(self) -> list[dict]:
        assets = self.store.assets()
        for extension in self.extensions:
            assets = extension.annotate_assets(self.store, assets)
        return assets


class Handler(BaseHTTPRequestHandler):
    server_version = f"Scout/{__version__}"

    def log_message(self, fmt, *args):
        line = fmt % args
        if "/api/status" in line and self.server.quiet_status:
            return
        # Never write the launch token to the terminal log.
        print(f"{self.address_string()} - {re.sub(r'token=[^ &]+', 'token=…', line)}")

    def _json(self, payload, status=200):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(raw)

    def _html(self, raw: bytes, status=200, cookie: str | None = None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers(); self.wfile.write(raw)

    def _session_cookie(self) -> str:
        """The launch token as a cookie, for the page's own reads (downloads, the static page).

        Lax, not Strict: the startup URL is usually opened from another app (a terminal), which the
        browser treats as a cross-site navigation, and Strict would withhold the cookie from exactly
        that request and every one after it until the next same-site navigation. Lax is sent on
        top-level GET navigations only. That lets another site start a download of an export, but not
        read it; and nothing a cross-site request can send changes anything, because every write needs
        the token in the X-Scout-Token header, which only this page can add."""
        return f"{self.server.cookie}={self.server.token}; Path=/; HttpOnly; SameSite=Lax"

    def _body(self, max_size=1_000_000):
        size = int(self.headers.get("Content-Length", "0"))
        if size < 0 or size > max_size:
            raise ValueError("Request is too large")
        return self.rfile.read(size)

    def _json_body(self):
        return json.loads(self._body().decode("utf-8") or "{}")

    # ------------------------------------------------------------------ the request boundary
    def _cookie_token(self) -> str | None:
        try:
            jar = SimpleCookie(self.headers.get("Cookie") or "")
        except Exception:
            return None
        morsel = jar.get(self.server.cookie)
        return morsel.value if morsel else None

    def _refuse_token(self, page: bool):
        name = self.server.edition.NAME
        message = (f"This request does not carry the token for the running {name}. Open the URL that "
                   f"run.py printed when it started (it includes ?token=…). Each launch has a new token.")
        if page:
            self._html(f"<!doctype html><meta charset=utf-8><title>{name}</title><p style='font:15px system-ui;"
                       f"max-width:40em;margin:3em auto'>{message}</p>".encode("utf-8"), status=401)
        else:
            self._json({"ok": False, "error": message, "token": "missing"}, status=401)

    def _permitted(self) -> bool:
        """Refuse anything that is not the assessor's own page, launched this time.

        Host says which name the browser thinks it is talking to, Origin says which page asked, and the
        token says the request comes from someone who saw this launch's startup line."""
        allowed = self.server.allowed_hosts
        seen = (self.headers.get("Host") or "")[:100]
        if not host_header_ok(self.headers.get("Host"), allowed):
            # Name what was refused and what to do about it. The value is one they sent us, so
            # echoing it back tells an attacker nothing they did not already know.
            self._json({"ok": False, "error": f"Unrecognised Host header \"{seen}\" — refused. If you reached "
                                              f"this through a proxy you set up, start the server with "
                                              f"--allowed-host {bare_host(seen) or '<name>'}."}, status=421)
            return False
        if self.command != "GET":
            if not origin_ok(self.headers.get("Origin"), allowed):
                self._json({"ok": False, "error": f"Cross-origin request refused: Origin "
                                                  f"\"{(self.headers.get('Origin') or '')[:100]}\" is not a name this "
                                                  f"server answers to."}, status=403)
                return False
            # The header, not the cookie: a cookie rides along on any request the browser is talked
            # into making, including from another port on localhost. A custom header does not.
            if not token_ok(self.headers.get(TOKEN_HEADER), self.server.token):
                self._refuse_token(page=False)
                return False
            return True
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            offered = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
            if offered:
                if not token_ok(offered, self.server.token):
                    self._refuse_token(page=True)
                    return False
                # Serve the page on this very response, with the cookie. A redirect would need the
                # browser to send the cookie straight back, which it may not do for a navigation that
                # began in another app. The page takes the token out of the address bar itself.
                self._html(self.server.page(), cookie=self._session_cookie())
                return False
        needs_token = path.startswith("/api/") or path in ("/", "/index.html")
        if needs_token and not (token_ok(self._cookie_token(), self.server.token)
                                or token_ok(self.headers.get(TOKEN_HEADER), self.server.token)):
            self._refuse_token(page=not path.startswith("/api/"))
            return False
        return True

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        if not self._permitted():
            return
        try:
            self._get(urlparse(self.path).path)
        except (ValueError, RuntimeError) as exc:
            self._json({"ok": False, "error": str(exc)}, 400)
        except Exception as exc:
            self._json({"ok": False, "error": f"Unexpected error: {exc}"}, 500)

    def _get(self, path: str):
        for extension in self.server.extensions:
            if extension.get(self, path):
                return
        store = self.server.store
        if path == "/api/status":
            db = self.server.database_status()
            return self._json({**self.server.capture.status(), **store.dashboard(), "coverage": store.coverage(),
                               "generation": store.generation, "dataset": db["current"], "engagement": db["engagement"]})
        if path == "/api/interfaces": return self._json(interfaces())
        if path == "/api/about":
            return self._json({"version": __version__, "name": self.server.edition.NAME,
                               "changelog": read_doc("changelog"), "guide": read_doc("guide")})
        if path == "/api/database": return self._json(self.server.database_status())
        if path == "/api/vendor-status": return self._json(store.vendor_status())
        if path == "/api/assets": return self._json(self.server.assets())
        if path == "/api/relationships": return self._json(store.relationships())
        if path == "/api/discovery": return self._json(store.discovery_traffic())
        if path == "/api/connections": return self._json(store.connections())
        if path == "/api/sessions": return self._json(store.sessions())
        if path == "/api/template/assets.csv": return self._download("asset-template.csv", store.asset_template_csv(), "text/csv")
        if path == "/api/asset-options":
            return self._json({"sources": store.ASSET_SOURCES, "support_statuses": store.SUPPORT_STATUSES, "backup_statuses": store.BACKUP_STATUSES, "levels": store.PURDUE_LEVELS})
        if path == "/api/zones":
            return self._json({**store.zone_summary(), "levels_list": store.PURDUE_LEVELS, "decisions_list": store.CONDUIT_DECISIONS})
        if path == "/api/export/purdue.svg":
            return self._download("purdue-zones.svg", store.purdue_svg().encode("utf-8"), "image/svg+xml")
        if path == "/api/findings":
            return self._json({"findings": store.findings(), "kinds": store.FINDING_KINDS, "ratings": store.FINDING_RATINGS,
                               "confidence": store.FINDING_CONFIDENCE, "horizons": store.FINDING_HORIZONS, "statuses": store.FINDING_STATUSES,
                               "frameworks": catalogue()})
        if path == "/api/findings/for":
            q = parse_qs(urlparse(self.path).query)
            kind, key = (q.get("kind") or [""])[0], (q.get("key") or [""])[0]
            return self._json({"kind": kind, "key": key, "findings": store.findings_for(kind, key)})
        if path == "/api/findings/drafts":
            return self._json(Analysis(collect(store), False).drafts)
        if path == "/api/export/assets.csv": return self._download("assets.csv", store.csv_export("assets"), "text/csv")
        if path == "/api/export/relationships.csv": return self._download("relationships.csv", store.csv_export("relationships"), "text/csv")
        if path == "/api/export/findings.csv": return self._download("findings.csv", store.csv_export("findings"), "text/csv")
        if path == "/api/export/discovery.csv": return self._download("discovery-traffic.csv", store.csv_export("discovery"), "text/csv")
        if path == "/api/export/connections.csv": return self._download("flows.csv", store.csv_export("flows"), "text/csv")
        if path == "/api/export/assessment.html":
            raw = build_html(store, self.server.edition.NAME, __version__).encode("utf-8")
            return self._download(f"{slug(self.server.edition.NAME)}-export.html", raw, "text/html; charset=utf-8")
        if path.startswith("/api/"):
            return self._json({"ok": False, "error": "Not found"}, status=404)
        if path in ("/", "/index.html"):
            return self._html(self.server.page())
        target = (STATIC / path.lstrip("/")).resolve()
        if STATIC.resolve() not in target.parents or not target.is_file() or target.suffix == ".html":
            return self.send_error(404)
        raw = target.read_bytes()
        self.send_response(200); self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

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

    # ------------------------------------------------------------------ POST
    def do_POST(self):
        if not self._permitted():
            return
        path = urlparse(self.path).path
        store = self.server.store
        try:
            for extension in self.server.extensions:
                if extension.post(self, path):
                    return
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
            if path == "/api/stop":
                self.server.capture.stop()
                hand_back(self.server.data_dir)
                return self._json({"ok": True})
            if path == "/api/update-vendors":
                if self.server.capture.running: raise ValueError("Stop capture before updating the vendor database")
                count = store.update_vendors()
                hand_back(self.server.data_dir)
                return self._json({"ok": True, "entries": count})
            if path == "/api/zones/accept-suggestions":
                body = self._json_body()
                count = store.accept_suggested_levels(int(body.get("min_confidence", 50)), bool(body.get("overwrite")))
                return self._json({"ok": True, "applied": count})
            if path == "/api/conduits":
                body = self._json_body()
                return self._json({"ok": True, "conduit": store.save_conduit(body.get("key_a", ""), body.get("key_b", ""), body)})
            if path == "/api/findings":
                return self._json({"ok": True, "finding": store.save_finding(self._json_body())})
            if path == "/api/findings/import-drafts":
                drafts = Analysis(collect(store), False).drafts
                return self._json({"ok": True, "added": store.import_draft_findings(drafts)})
            if path.startswith("/api/findings/"):
                parts = path.strip("/").split("/")
                if len(parts) != 4 or not parts[2].isdigit() or parts[3] != "delete":
                    raise ValueError("Invalid finding request")
                store.delete_finding(int(parts[2])); return self._json({"ok": True})
            if path == "/api/assets/new":
                return self._json({"ok": True, "asset": store.add_documented_asset(self._json_body())})
            if path == "/api/import-assets":
                raw = self._body(20 * 1024 * 1024)
                result = store.import_assets_csv(raw, self.headers.get("X-Source", "").strip() or "Spreadsheet import")
                return self._json({"ok": True, **result})
            if path.startswith("/api/assets/"):
                parts = path.strip("/").split("/")
                if len(parts) < 3 or not parts[2].isdigit():
                    raise ValueError("Invalid asset identifier")
                asset_id, action = int(parts[2]), parts[3] if len(parts) > 3 else ""
                if action == "merge":
                    body = self._json_body()
                    return self._json({"ok": True, "asset": store.merge_assets(asset_id, int(body.get("secondary", 0)), str(body.get("note", "")))})
                if action == "delete":
                    store.delete_asset(asset_id); return self._json({"ok": True})
                if action:
                    raise ValueError("Unknown asset action")
                item = store.update_asset(asset_id, self._json_body())
                return self._json({"ok": True, "asset": item})
            if path == "/api/import-pcap":
                if self.server.capture.running:
                    raise ValueError("Stop the live capture before importing a PCAP. Parsing the file competes with the live reader for the CPU and the database, and that is what causes kernel drops.")
                data = self._body(MAX_UPLOAD)
                meta = {k: self.headers.get(h, "").strip() for k, h in {
                    "assessment": "X-Assessment", "site": "X-Site", "point": "X-Collection-Point", "filename": "X-Filename"}.items()}
                if any(not v for v in meta.values()): raise ValueError("PCAP import metadata is incomplete")
                try:
                    rate_limit = int(self.headers.get("X-Rate-Limit", "") or 0) or None
                except ValueError:
                    rate_limit = None
                result = self.server.capture.import_pcap(data, meta["assessment"], meta["site"], meta["point"], meta["filename"], rate_limit=rate_limit)
                return self._json({"ok": True, **result})
            self._json({"ok": False, "error": "Not found"}, status=404)
        except (ValueError, RuntimeError, json.JSONDecodeError) as exc:
            self._json({"ok": False, "error": str(exc)}, 400)
        except Exception as exc:
            self._json({"ok": False, "error": f"Unexpected error: {exc}"}, 500)
