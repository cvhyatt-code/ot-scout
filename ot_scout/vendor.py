from __future__ import annotations

import csv
import io
import urllib.request
from pathlib import Path

from . import __version__


IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


class VendorLookup:
    def __init__(self, data_path: str | Path):
        self.data_path = Path(data_path)
        self.prefixes: dict[str, str] = {}
        self.load()

    def load(self):
        self.prefixes = {}
        for path in (self.data_path, Path("/usr/share/ieee-data/oui.csv")):
            if not path.is_file():
                continue
            try:
                with path.open(encoding="utf-8", errors="replace", newline="") as stream:
                    for row in csv.DictReader(stream):
                        prefix = (row.get("Assignment") or row.get("assignment") or "").replace(":", "").replace("-", "").upper()
                        vendor = (row.get("Organization Name") or row.get("organization_name") or "").strip()
                        if len(prefix) >= 6 and vendor:
                            self.prefixes[prefix[:6]] = vendor
                if self.prefixes:
                    return
            except OSError:
                pass
        self._load_text_databases()

    def _load_text_databases(self):
        for path in (Path("/usr/share/nmap/nmap-mac-prefixes"), Path("/usr/share/wireshark/manuf")):
            if not path.is_file():
                continue
            try:
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.replace(":", "").replace("-", "").split(None, 1)
                    if len(parts) == 2 and len(parts[0]) >= 6:
                        self.prefixes[parts[0][:6].upper()] = parts[1].strip()
                if self.prefixes:
                    return
            except OSError:
                pass

    def lookup(self, mac: str) -> str:
        compact = mac.replace(":", "").replace("-", "").upper()
        if len(compact) < 6:
            return ""
        try:
            if int(compact[:2], 16) & 2:
                return "Locally administered"
        except ValueError:
            return ""
        return self.prefixes.get(compact[:6], "")

    def update(self) -> int:
        request = urllib.request.Request(IEEE_OUI_URL, headers={"User-Agent": f"OT-Scout/{__version__}"})
        with urllib.request.urlopen(request, timeout=45) as response:
            data = response.read(20 * 1024 * 1024 + 1)
        if len(data) > 20 * 1024 * 1024:
            raise ValueError("IEEE vendor database exceeded the safety limit")
        text = data.decode("utf-8-sig", "replace")
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames or "Assignment" not in reader.fieldnames or "Organization Name" not in reader.fieldnames:
            raise ValueError("Downloaded file is not an IEEE OUI database")
        count = sum(1 for row in reader if row.get("Assignment") and row.get("Organization Name"))
        if count < 1000:
            raise ValueError("Downloaded IEEE OUI database is unexpectedly small")
        self.data_path.parent.mkdir(parents=True, exist_ok=True)
        self.data_path.write_text(text, encoding="utf-8")
        self.load()
        return len(self.prefixes)
