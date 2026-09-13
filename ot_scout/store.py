from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from .parser import PacketObservation
from .vendor import VendorLookup


def iso_time(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else datetime.now(timezone.utc).isoformat(timespec="seconds")


def duration_seconds(started_at: str, ended_at: str | None) -> int | None:
    """Whole seconds between two ISO timestamps; an open session is measured to now."""
    try:
        start = datetime.fromisoformat(started_at)
        end = datetime.fromisoformat(ended_at) if ended_at else datetime.now(timezone.utc)
    except (TypeError, ValueError):
        return None
    return max(0, int((end - start).total_seconds()))


def format_duration(seconds: int | None) -> str:
    if seconds is None:
        return ""
    hours, rest = divmod(int(seconds), 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


GENERIC_NAMES = {"localhost", "localhost.localdomain", "unknown", "unnamed", "default", "device", "host", "router", "gateway"}


def informative_name(name: str, mac: str = "") -> bool:
    """Reject hostnames that only restate the MAC/IP or are placeholders such as localhost."""
    base = name.strip().rstrip(".").lower()
    if not base:
        return False
    stem = re.sub(r"\.(local|lan|localdomain|home|arpa)$", "", base)
    if stem in GENERIC_NAMES:
        return False
    compact = re.sub(r"[^0-9a-f]", "", stem)
    mac_compact = re.sub(r"[^0-9a-f]", "", mac.lower())
    if mac_compact and compact.startswith(mac_compact):
        return False
    if re.fullmatch(r"[0-9a-f]{12,}", compact) and re.fullmatch(r"[0-9a-f:\-_]+", stem):
        return False
    if re.fullmatch(r"(\d{1,3}[-.]){3}\d{1,3}", stem):
        return False
    return True


def unicast_mac(mac: str) -> bool:
    try:
        return bool(mac and mac != "00:00:00:00:00:00" and not (int(mac[:2], 16) & 1))
    except (ValueError, IndexError):
        return False


def locally_administered(mac: str) -> bool:
    try:
        return bool(int(mac[:2], 16) & 2)
    except (ValueError, IndexError):
        return False


def endpoint_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return False


def broadcast_or_multicast_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_multicast or value == "255.255.255.255"
    except ValueError:
        return False


# RFC 5737 and RFC 3849. Python counts these as private, because they are not globally routable.
# For an assessment the question is a different one — is this address part of the site? — and these
# are not: they should never appear on a plant network, so a controller talking to one is an anomaly
# worth surfacing rather than a row quietly filed as "Unmapped local".
DOCUMENTATION_NETS = tuple(ipaddress.ip_network(n) for n in
                           ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


def private_or_local_ip(value: str) -> bool:
    """True if this address belongs to the site's own network rather than somewhere outside it."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if any(ip in net for net in DOCUMENTATION_NETS):
        return False
    return ip.is_private or ip.is_link_local


class Store:
    EDITABLE_ASSET_FIELDS = {
        "manual_type": 100, "location": 200, "criticality": 40, "purdue_level": 40,
        "zone": 100, "process_function": 200, "safety_impact": 500, "owner": 200, "notes": 2000,
        "vendor": 200, "model": 200, "serial": 200, "firmware": 100, "asset_tag": 100, "source": 60,
        "install_date": 40, "end_of_life": 40, "end_of_support": 40, "support_status": 60,
        "patch_status": 200, "backup_status": 60, "last_backup": 40,
    }
    ASSET_SOURCES = ("Passive capture", "Physical walkdown", "Drawing / documentation", "Interview", "Customer inventory", "Spreadsheet import")
    SUPPORT_STATUSES = ("", "Supported", "Extended support", "End of life", "End of support", "Unknown")
    BACKUP_STATUSES = ("", "Backed up and tested", "Backed up, untested", "No backup", "Not applicable", "Unknown")
    TEMPLATE_COLUMNS = ["name", "mac", "ip", "asset_tag", "manufacturer", "model", "serial", "firmware", "device_type",
                        "location", "criticality", "purdue_level", "zone", "process_function", "safety_impact", "owner",
                        "source", "install_date", "end_of_life", "end_of_support", "support_status", "patch_status",
                        "backup_status", "last_backup", "notes"]

    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.vendors = VendorLookup(Path(self.path).parent / "oui.csv")
        self.generation = 0          # incremented on every write; computed views are cached per generation
        self._cache: dict = {}
        self._init()

    def _bump(self):
        self.generation += 1
        self._cache = {}

    def _cached(self, key, compute):
        hit = self._cache.get(key)
        if hit and hit[0] == self.generation:
            return hit[1]
        value = compute()
        self._cache[key] = (self.generation, value)
        return value

    def connect(self):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def _init(self):
        with self.connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
              id INTEGER PRIMARY KEY, assessment TEXT NOT NULL, site TEXT NOT NULL,
              collection_point TEXT NOT NULL, interface TEXT NOT NULL,
              started_at TEXT NOT NULL, ended_at TEXT, packets INTEGER NOT NULL DEFAULT 0,
              bytes INTEGER NOT NULL DEFAULT 0, source_type TEXT NOT NULL DEFAULT 'live',
              access_method TEXT NOT NULL DEFAULT 'Unconfirmed access port',
              third_party_unicast INTEGER NOT NULL DEFAULT 0,
              local_unicast INTEGER NOT NULL DEFAULT 0,
              broadcast_multicast INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS assets (
              id INTEGER PRIMARY KEY, mac TEXT NOT NULL UNIQUE, vendor TEXT NOT NULL DEFAULT '',
              model TEXT NOT NULL DEFAULT '', serial TEXT NOT NULL DEFAULT '', firmware TEXT NOT NULL DEFAULT '',
              manual_type TEXT NOT NULL DEFAULT '', location TEXT NOT NULL DEFAULT '',
              criticality TEXT NOT NULL DEFAULT '', purdue_level TEXT NOT NULL DEFAULT '',
              zone TEXT NOT NULL DEFAULT '', process_function TEXT NOT NULL DEFAULT '',
              safety_impact TEXT NOT NULL DEFAULT '', owner TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
              first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, packets INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS asset_ips (
              asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
              ip TEXT NOT NULL, evidence TEXT NOT NULL, confidence INTEGER NOT NULL,
              first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, packets INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY(asset_id,ip,evidence)
            );
            CREATE TABLE IF NOT EXISTS asset_names (
              asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
              name TEXT NOT NULL, evidence TEXT NOT NULL, confidence INTEGER NOT NULL,
              first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, packets INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY(asset_id,name,evidence)
            );
            CREATE TABLE IF NOT EXISTS fingerprints (
              asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
              field TEXT NOT NULL, value TEXT NOT NULL, evidence TEXT NOT NULL,
              confidence INTEGER NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
              packets INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY(asset_id,field,value,evidence)
            );
            CREATE TABLE IF NOT EXISTS dns_names (
              ip TEXT NOT NULL, name TEXT NOT NULL, evidence TEXT NOT NULL,
              first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, packets INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY(ip,name,evidence)
            );
            CREATE TABLE IF NOT EXISTS sightings (
              asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
              session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
              vlan TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
              packets INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(asset_id,session_id,vlan)
            );
            CREATE TABLE IF NOT EXISTS connections (
              id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
              src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, transport TEXT NOT NULL,
              src_port INTEGER NOT NULL DEFAULT -1, dst_port INTEGER NOT NULL DEFAULT -1,
              app_protocol TEXT NOT NULL, vlan TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL, packets INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
              traffic_scope TEXT NOT NULL DEFAULT 'Unicast',
              UNIQUE(session_id,src_ip,dst_ip,transport,src_port,dst_port,app_protocol,vlan,traffic_scope)
            );
            CREATE TABLE IF NOT EXISTS sites (
              id INTEGER PRIMARY KEY, assessment TEXT NOT NULL DEFAULT '', name TEXT NOT NULL,
              facility_type TEXT NOT NULL DEFAULT '', operational_function TEXT NOT NULL DEFAULT '',
              contacts TEXT NOT NULL DEFAULT '', walkdown_date TEXT NOT NULL DEFAULT '',
              documentation TEXT NOT NULL DEFAULT '', deviations TEXT NOT NULL DEFAULT '',
              notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              UNIQUE(assessment,name)
            );
            CREATE TABLE IF NOT EXISTS site_checklist (
              site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
              item TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Not started',
              evidence TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
              PRIMARY KEY(site_id,item)
            );
            CREATE TABLE IF NOT EXISTS network_legs (
              id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
              name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', purdue_level TEXT NOT NULL DEFAULT '',
              evidence_source TEXT NOT NULL DEFAULT 'None yet', collection_point TEXT NOT NULL DEFAULT '',
              status TEXT NOT NULL DEFAULT 'Planned', time_window TEXT NOT NULL DEFAULT '',
              exclusions TEXT NOT NULL DEFAULT '', limitations TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            """)
            db.executescript("""
            CREATE TABLE IF NOT EXISTS conduits (
              key_a TEXT NOT NULL, key_b TEXT NOT NULL, decision TEXT NOT NULL DEFAULT 'Unknown',
              purpose TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
              PRIMARY KEY(key_a,key_b)
            );
            CREATE TABLE IF NOT EXISTS findings (
              id INTEGER PRIMARY KEY, ref TEXT NOT NULL DEFAULT '', title TEXT NOT NULL,
              kind TEXT NOT NULL DEFAULT 'Evidence gap', rating TEXT NOT NULL DEFAULT 'Moderate',
              confidence TEXT NOT NULL DEFAULT 'Moderate', owner TEXT NOT NULL DEFAULT '',
              condition TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '', impact TEXT NOT NULL DEFAULT '',
              recommendation TEXT NOT NULL DEFAULT '', closure TEXT NOT NULL DEFAULT '',
              horizon TEXT NOT NULL DEFAULT '30-90 days', status TEXT NOT NULL DEFAULT 'Draft',
              site TEXT NOT NULL DEFAULT '', assets TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'Assessor',
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            """)
            existing = {r[1] for r in db.execute("PRAGMA table_info(assets)")}
            for column in ("purdue_source", "source", "asset_tag", "install_date", "end_of_life", "end_of_support",
                           "support_status", "patch_status", "backup_status", "last_backup"):
                if column not in existing:
                    db.execute(f"ALTER TABLE assets ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
            existing = {r[1] for r in db.execute("PRAGMA table_info(sessions)")}
            for column, decl in (("dropped", "INTEGER NOT NULL DEFAULT 0"), ("frames", "INTEGER NOT NULL DEFAULT 0"), ("pcap_path", "TEXT NOT NULL DEFAULT ''")):
                if column not in existing:
                    db.execute(f"ALTER TABLE sessions ADD COLUMN {column} {decl}")
            existing = {r[1] for r in db.execute("PRAGMA table_info(findings)")}
            for column in ("iec62443", "attack", "draft_key"):
                if column not in existing:
                    db.execute(f"ALTER TABLE findings ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
            db.executescript("""
            CREATE TABLE IF NOT EXISTS finding_links (
              finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
              kind TEXT NOT NULL, key TEXT NOT NULL,
              PRIMARY KEY(finding_id,kind,key)
            );
            CREATE TABLE IF NOT EXISTS asset_aliases (
              mac TEXT PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
              note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
            );
            """)
            stale = [(row[0], row[1]) for row in db.execute("SELECT n.asset_id,n.name FROM asset_names n JOIN assets a ON a.id=n.asset_id")
                     if not informative_name(row[1], db.execute("SELECT mac FROM assets WHERE id=?", (row[0],)).fetchone()[0])]
            for asset_id, name in stale:
                db.execute("DELETE FROM asset_names WHERE asset_id=? AND name=?", (asset_id, name))

    def begin_session(self, assessment: str, site: str, point: str, interface: str,
                      source_type: str = "live", access_method: str = "Unconfirmed access port") -> int:
        self._bump()
        with self.lock, self.connect() as db:
            cur = db.execute(
                "INSERT INTO sessions(assessment,site,collection_point,interface,started_at,source_type,access_method) VALUES(?,?,?,?,?,?,?)",
                (assessment, site, point, interface, iso_time(), source_type, access_method),
            )
            return int(cur.lastrowid)

    def end_session(self, session_id: int, dropped: int | None = None, frames: int | None = None):
        self._bump()
        with self.lock, self.connect() as db:
            db.execute("UPDATE sessions SET ended_at=? WHERE id=?", (iso_time(), session_id))
            if dropped is not None:
                db.execute("UPDATE sessions SET dropped=? WHERE id=?", (int(dropped), session_id))
            if frames is not None:
                db.execute("UPDATE sessions SET frames=? WHERE id=?", (int(frames), session_id))

    def set_session_pcap(self, session_id: int, path: str):
        self._bump()
        with self.lock, self.connect() as db:
            db.execute("UPDATE sessions SET pcap_path=? WHERE id=?", (path, session_id))

    def _asset(self, db, mac: str, seen: str, session_id: int, vlan: str) -> int | None:
        if not unicast_mac(mac):
            return None
        alias = db.execute("SELECT asset_id FROM asset_aliases WHERE mac=?", (mac,)).fetchone()
        if alias:
            db.execute("UPDATE assets SET last_seen=?,packets=packets+1 WHERE id=?", (seen, alias[0]))
            db.execute("""
              INSERT INTO sightings(asset_id,session_id,vlan,first_seen,last_seen,packets) VALUES(?,?,?,?,?,1)
              ON CONFLICT(asset_id,session_id,vlan) DO UPDATE SET last_seen=excluded.last_seen,packets=sightings.packets+1
            """, (alias[0], session_id, vlan, seen, seen))
            return alias[0]
        vendor = self.vendors.lookup(mac)
        db.execute("""
          INSERT INTO assets(mac,vendor,first_seen,last_seen,packets) VALUES(?,?,?,?,1)
          ON CONFLICT(mac) DO UPDATE SET vendor=CASE WHEN assets.vendor='' THEN excluded.vendor ELSE assets.vendor END,
            last_seen=excluded.last_seen,packets=assets.packets+1
        """, (mac, vendor, seen, seen))
        asset_id = db.execute("SELECT id FROM assets WHERE mac=?", (mac,)).fetchone()[0]
        db.execute("""
          INSERT INTO sightings(asset_id,session_id,vlan,first_seen,last_seen,packets) VALUES(?,?,?,?,?,1)
          ON CONFLICT(asset_id,session_id,vlan) DO UPDATE SET last_seen=excluded.last_seen,packets=sightings.packets+1
        """, (asset_id, session_id, vlan, seen, seen))
        return asset_id

    def _ip(self, db, asset_id: int | None, ip: str, evidence: str, confidence: int, seen: str):
        if not asset_id or not endpoint_ip(ip):
            return
        db.execute("""
          INSERT INTO asset_ips(asset_id,ip,evidence,confidence,first_seen,last_seen,packets) VALUES(?,?,?,?,?,?,1)
          ON CONFLICT(asset_id,ip,evidence) DO UPDATE SET last_seen=excluded.last_seen,packets=asset_ips.packets+1,
            confidence=max(asset_ips.confidence,excluded.confidence)
        """, (asset_id, ip, evidence, confidence, seen, seen))

    def _name(self, db, asset_id: int | None, name: str, evidence: str, confidence: int, seen: str):
        name = name.strip().rstrip(".")[:255]
        if not asset_id or not name:
            return
        mac = db.execute("SELECT mac FROM assets WHERE id=?", (asset_id,)).fetchone()[0]
        if not informative_name(name, mac):
            return
        db.execute("""
          INSERT INTO asset_names(asset_id,name,evidence,confidence,first_seen,last_seen,packets) VALUES(?,?,?,?,?,?,1)
          ON CONFLICT(asset_id,name,evidence) DO UPDATE SET last_seen=excluded.last_seen,packets=asset_names.packets+1,
            confidence=max(asset_names.confidence,excluded.confidence)
        """, (asset_id, name, evidence, confidence, seen, seen))

    def _fingerprint(self, db, asset_id: int | None, field: str, value: str, evidence: str, confidence: int, seen: str):
        field, value, evidence = field.strip()[:64], value.strip()[:512], evidence.strip()[:255]
        if not asset_id or not field or not value or not evidence:
            return
        db.execute("""
          INSERT INTO fingerprints(asset_id,field,value,evidence,confidence,first_seen,last_seen,packets)
          VALUES(?,?,?,?,?,?,?,1)
          ON CONFLICT(asset_id,field,value,evidence) DO UPDATE SET last_seen=excluded.last_seen,
            packets=fingerprints.packets+1,confidence=max(fingerprints.confidence,excluded.confidence)
        """, (asset_id, field, value, evidence, max(0, min(100, confidence)), seen, seen))

    def record(self, session_id: int, obs: PacketObservation, local_mac: str = ""):
        self._bump()
        with self.lock, self.connect() as db:
            self._record(db, session_id, obs, local_mac)

    def record_many(self, session_id: int, batch: list[PacketObservation], local_mac: str = ""):
        """One connection and one transaction for a whole batch — the per-packet variant spends ~99% of
        its time opening a connection and committing, so this is the difference between ~1k and ~20k+ pkt/s."""
        if not batch:
            return
        self._bump()
        with self.lock, self.connect() as db:
            db.execute("BEGIN")
            for obs in batch:
                self._record(db, session_id, obs, local_mac)

    def _record(self, db, session_id: int, obs: PacketObservation, local_mac: str = ""):
        seen = iso_time(obs.timestamp)
        vlan = "" if obs.vlan is None else str(obs.vlan)
        if True:
            destination_multicast = not unicast_mac(obs.dst_mac)
            local_mac = local_mac.lower()
            if destination_multicast:
                visibility_column = "broadcast_multicast"
            elif local_mac and obs.src_mac.lower() != local_mac and obs.dst_mac.lower() != local_mac:
                visibility_column = "third_party_unicast"
            else:
                visibility_column = "local_unicast"
            db.execute(f"UPDATE sessions SET packets=packets+1,bytes=bytes+?,{visibility_column}={visibility_column}+1 WHERE id=?", (obs.length, session_id))
            src_asset = self._asset(db, obs.src_mac, seen, session_id, vlan)
            dst_asset = self._asset(db, obs.dst_mac, seen, session_id, vlan)
            if obs.app_protocol == "ARP":
                self._ip(db, src_asset, obs.src_ip, "ARP sender", 100, seen)
                self._ip(db, dst_asset, obs.dst_ip, "ARP target", 100, seen)
            else:
                self._ip(db, src_asset, obs.src_ip, "Frame source", 60, seen)
            if obs.app_protocol == "DHCP":
                self._ip(db, src_asset, obs.src_ip, "DHCP", 100, seen)
                self._name(db, src_asset, obs.source_name, "DHCP hostname", 100, seen)
            elif obs.app_protocol == "PROFINET-DCP" and obs.source_name:
                self._name(db, src_asset, obs.source_name, "Profinet station name", 100, seen)
                if obs.src_ip:
                    self._ip(db, src_asset, obs.src_ip, "PN-DCP IP parameter", 95, seen)
            for field, value, evidence, confidence in obs.fingerprints:
                self._fingerprint(db, src_asset, field, value, evidence, confidence, seen)
            for field, value, evidence, confidence in obs.dst_fingerprints:
                self._fingerprint(db, dst_asset, field, value, evidence, confidence, seen)
            for name, evidence in obs.dst_name_claims:
                self._name(db, dst_asset, name, evidence, 80, seen)
            for ip, name in obs.name_claims:
                if not endpoint_ip(ip) or not name:
                    continue
                evidence = obs.app_protocol
                db.execute("""
                  INSERT INTO dns_names(ip,name,evidence,first_seen,last_seen,packets) VALUES(?,?,?,?,?,1)
                  ON CONFLICT(ip,name,evidence) DO UPDATE SET last_seen=excluded.last_seen,packets=dns_names.packets+1
                """, (ip, name.rstrip("."), evidence, seen, seen))
                if evidence in ("MDNS", "LLMNR"):
                    for row in db.execute("SELECT DISTINCT asset_id FROM asset_ips WHERE ip=?", (ip,)):
                        self._name(db, row[0], name, evidence, 85, seen)
            if obs.src_ip and obs.dst_ip:
                traffic_scope = "Broadcast/multicast" if destination_multicast or broadcast_or_multicast_ip(obs.dst_ip) else "Unicast"
                db.execute("""
                  INSERT INTO connections(session_id,src_ip,dst_ip,transport,src_port,dst_port,app_protocol,vlan,first_seen,last_seen,packets,bytes,traffic_scope)
                  VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?)
                  ON CONFLICT(session_id,src_ip,dst_ip,transport,src_port,dst_port,app_protocol,vlan,traffic_scope)
                  DO UPDATE SET last_seen=excluded.last_seen,packets=connections.packets+1,bytes=connections.bytes+excluded.bytes
                """, (session_id, obs.src_ip, obs.dst_ip, obs.transport, obs.src_port if obs.src_port is not None else -1,
                      obs.dst_port if obs.dst_port is not None else -1, obs.app_protocol, vlan, seen, seen, obs.length, traffic_scope))

    @staticmethod
    def _derived_identity(mac: str, all_macs: set[str]) -> bool:
        if not locally_administered(mac):
            return False
        parts = mac.split(":")
        return any(not locally_administered(other) and len(parts) == 6 and parts[1:5] == other.split(":")[1:5] for other in all_macs)

    @staticmethod
    def _secondary_interface(mac: str, primaries: dict[str, int]) -> str:
        """Return the MAC of a same-OUI device with IP evidence whose address is within 16 of this one.
        Access points, managed switches and multi-port controllers present adjacent MACs per radio/port."""
        try:
            value = int(mac.replace(":", ""), 16)
        except ValueError:
            return ""
        oui = mac[:8]
        best = ""
        for other, other_value in primaries.items():
            if other != mac and other[:8] == oui and 0 < abs(other_value - value) <= 16:
                if not best or abs(other_value - value) < abs(primaries[best] - value):
                    best = other
        return best

    @staticmethod
    def _best(rows: list[dict], fields: tuple[str, ...]) -> dict | None:
        choices = [row for row in rows if row["field"] in fields]
        return max(choices, key=lambda row: (row["confidence"], row["packets"])) if choices else None

    def _automatic_type(self, item: dict, fingerprints: list[dict], protocols: set[str]) -> tuple[str, int, str]:
        if item["classification"] == "Gateway/transit MAC":
            return "Gateway/router", 95, item["classification_evidence"]
        if item["classification"] == "Likely virtual/derived identity":
            return "Virtual interface", 85, item["classification_evidence"]
        role = self._best(fingerprints, ("role",))
        if role:
            return role["value"], role["confidence"], role["evidence"]
        protocol_types = {"MODBUS-TCP": "Modbus device", "S7COMM": "Siemens S7 device",
                          "ETHERNET-IP": "EtherNet/IP device", "ETHERNET-IP-IO": "EtherNet/IP device",
                          "BACNET-IP": "BACnet device", "DNP3": "DNP3 device", "OPC-UA": "OPC UA system",
                          "PROFINET-RT": "Profinet device", "PROFINET-DCP": "Profinet device"}
        for protocol, label in protocol_types.items():
            if protocol in protocols:
                return label, 75, f"Observed {protocol} traffic; payload identity not confirmed"
        vendor = item["manufacturer"].lower()
        if "yealink" in vendor:
            return "VoIP phone", 75, "Specialized manufacturer from MAC OUI"
        if any(name in vendor for name in ("eero", "ubiquiti", "ruckus", "aruba", "cisco", "juniper", "netgear", "tp-link", "humax")):
            return "Network infrastructure", 70, "Network-equipment manufacturer from MAC OUI"
        if "wyze" in vendor:
            return "Camera / IoT device", 65, "Wyze manufacturer OUI; exact product not passively confirmed"
        if "espressif" in vendor or "linksprite" in vendor:
            return "Embedded / IoT device", 60, "Embedded-device manufacturer from MAC OUI"
        if "amazon" in vendor:
            return "Amazon consumer / IoT device", 55, "Amazon manufacturer OUI; exact product not passively confirmed"
        if "apple" in vendor:
            return "Apple user endpoint", 55, "Apple manufacturer from MAC OUI"
        if any(name in vendor for name in ("dell", "lenovo", "hewlett", "intel")):
            return "Computer/workstation", 55, "Computer-component manufacturer from MAC OUI"
        if any(name in vendor for name in ("ampak", "azurewave", "gaoshengda")):
            return "Embedded / consumer device", 45, "Wireless-module manufacturer from MAC OUI"
        if item["classification"] == "Locally administered endpoint":
            return "Private/randomized-MAC endpoint", 35, "Locally administered MAC with direct IP evidence"
        return "Unclassified endpoint", 25, "Insufficient passive evidence"

    @staticmethod
    def _network_vendor(vendor: str) -> bool:
        value = vendor.lower()
        return any(name in value for name in ("eero", "ubiquiti", "ruckus", "aruba", "cisco", "juniper", "netgear", "tp-link", "humax"))

    def assets(self) -> list[dict]:
        return self._cached("assets", self._assets)

    def assets_with_exposure(self) -> list[dict]:
        """assets() plus exposure score, band and factors per physical asset (see exposure.py)."""
        return self._cached("assets_exposure", self._assets_with_exposure)

    def _assets_with_exposure(self) -> list[dict]:
        from .exposure import annotate
        base = self.assets()
        rels = self.relationships(100000, base)
        served: dict[int, set[int]] = {}
        with self.connect() as db:
            ip_to_asset = {row[0]: row[1] for row in db.execute("SELECT ip,asset_id FROM asset_ips")}
            for ip, port in db.execute("SELECT DISTINCT dst_ip,dst_port FROM connections WHERE dst_port IN (21,23,69,80,161,5900) AND traffic_scope='Unicast'"):
                if ip in ip_to_asset:
                    served.setdefault(ip_to_asset[ip], set()).add(port)
        annotated = [dict(a) for a in base]
        annotate(annotated, rels, served, self.findings())
        return annotated

    def _assets(self) -> list[dict]:
        with self.connect() as db:
            raw = [dict(row) for row in db.execute("""
              SELECT a.*,
                (SELECT count(DISTINCT ip) FROM asset_ips ai WHERE ai.asset_id=a.id AND ai.evidence='Frame source') source_ip_count,
                (SELECT name FROM asset_names n WHERE n.asset_id=a.id ORDER BY confidence DESC,packets DESC LIMIT 1) name,
                (SELECT evidence FROM asset_names n WHERE n.asset_id=a.id ORDER BY confidence DESC,packets DESC LIMIT 1) name_evidence,
                group_concat(DISTINCT s.collection_point) collection_points,
                group_concat(DISTINCT s.interface) interfaces,
                group_concat(DISTINCT NULLIF(si.vlan,'')) vlans
              FROM assets a LEFT JOIN sightings si ON si.asset_id=a.id LEFT JOIN sessions s ON s.id=si.session_id
              GROUP BY a.id ORDER BY a.packets DESC,a.mac
            """)]
            all_macs = {item["mac"] for item in raw}
            ports = ",".join(str(p) for p in self.INDUSTRIAL_SERVER_PORTS)
            role_index = {"served": {}, "spoke": {}}
            proto_index: dict[str, set] = {}
            for src, dst, proto in db.execute("SELECT DISTINCT src_ip,dst_ip,app_protocol FROM connections"):
                proto_index.setdefault(src, set()).add(proto); proto_index.setdefault(dst, set()).add(proto)
            for ip, port, n in db.execute(f"SELECT dst_ip,dst_port,count(*) FROM connections WHERE dst_port IN ({ports}) GROUP BY dst_ip,dst_port"):
                role_index["served"].setdefault(ip, {})[port] = n
            for ip, port, n in db.execute(f"SELECT src_ip,dst_port,count(*) FROM connections WHERE dst_port IN ({ports}) GROUP BY src_ip,dst_port"):
                role_index["spoke"].setdefault(ip, {})[port] = n
            with_ip = {row[0] for row in db.execute("SELECT DISTINCT a.mac FROM assets a JOIN asset_ips ai ON ai.asset_id=a.id")}
            primaries = {}
            for mac in with_ip:
                try:
                    primaries[mac] = int(mac.replace(":", ""), 16)
                except ValueError:
                    pass
            result = []
            for item in raw:
                item["name"], item["name_evidence"] = item["name"] or "", item["name_evidence"] or ""
                ip_rows = [dict(row) for row in db.execute(
                    "SELECT ip,evidence,confidence,packets,first_seen,last_seen FROM asset_ips WHERE asset_id=? ORDER BY confidence DESC,packets DESC,ip",
                    (item["id"],))]
                direct_ips = list(dict.fromkeys(row["ip"] for row in ip_rows if row["evidence"] != "Frame source"))
                frame_ips = list(dict.fromkeys(row["ip"] for row in ip_rows if row["evidence"] == "Frame source"))
                recognized_transit = (self._network_vendor(item["vendor"]) and
                                      any(private_or_local_ip(ip) for ip in direct_ips) and
                                      any(not private_or_local_ip(ip) for ip in frame_ips))
                gateway = item["source_ip_count"] > 8 or recognized_transit
                trusted_ips = direct_ips if gateway else list(dict.fromkeys(direct_ips + frame_ips))
                item["ips"] = ",".join(trusted_ips)
                item["ip_evidence"] = ip_rows
                item["suppressed_transit_ips"] = len([ip for ip in frame_ips if ip not in direct_ips]) if gateway else 0
                if item["mac"].startswith("manual:") or (item["packets"] == 0 and item["source"] and item["source"] != "Passive capture"):
                    item.update(classification="Documented, not observed", classification_evidence=f"Recorded from {item['source'] or 'assessor entry'}; no passive evidence yet", physical_asset=True)
                elif gateway:
                    reason = (f"Network-equipment OUI plus direct local IP and {item['suppressed_transit_ips']} routed source IP(s)"
                              if recognized_transit else f"Observed with {item['source_ip_count']} frame-source IPs")
                    item.update(classification="Gateway/transit MAC", classification_evidence=reason, physical_asset=True)
                elif self._derived_identity(item["mac"], all_macs) and not trusted_ips:
                    item.update(classification="Likely virtual/derived identity", classification_evidence="Locally administered MAC pattern matches another observed device and has no IP evidence", physical_asset=False)
                elif not trusted_ips and not locally_administered(item["mac"]) and self._network_vendor(item["vendor"]) and (primary := self._secondary_interface(item["mac"], primaries)):
                    item.update(classification="Likely secondary interface", classification_evidence=f"Network-equipment OUI, adjacent MAC to {primary}, no IP evidence; typical of an additional radio, port or BSSID on the same device", physical_asset=False)
                elif locally_administered(item["mac"]):
                    item.update(classification="Locally administered endpoint", classification_evidence="MAC is locally administered; physical identity requires corroboration", physical_asset=True)
                else:
                    item.update(classification="Physical endpoint", classification_evidence="Globally administered MAC observed on Ethernet", physical_asset=True)
                if item["source"] and item["source"] != "Passive capture" and item["packets"] and item["classification"] != "Documented, not observed":
                    item["classification_evidence"] += f"; corroborated by documented record ({item['source']})"
                fingerprint_rows = [dict(row) for row in db.execute("SELECT field,value,evidence,confidence,packets FROM fingerprints WHERE asset_id=? ORDER BY confidence DESC,packets DESC", (item["id"],))]
                manufacturer = self._best(fingerprint_rows, ("manufacturer",))
                item["manufacturer"] = item["vendor"] if item["source"] and item["source"] != "Passive capture" and item["vendor"] else (manufacturer["value"] if manufacturer else item["vendor"])
                item["source"] = item["source"] or "Passive capture"
                item["aliases"] = [r[0] for r in db.execute("SELECT mac FROM asset_aliases WHERE asset_id=?", (item["id"],))]
                for field, candidates in (("model", ("model", "product_name", "product_code")), ("serial", ("serial",)), ("firmware", ("firmware",))):
                    detected = self._best(fingerprint_rows, candidates)
                    if not item[field] and detected:
                        item[field] = detected["value"]
                protocols = set()
                for ip in trusted_ips:
                    protocols |= proto_index.get(ip, set())
                auto_type, confidence, evidence = self._automatic_type(item, fingerprint_rows, protocols)
                item.update(auto_type=auto_type, type_confidence=confidence, type_evidence=evidence,
                            display_type=item["manual_type"] or auto_type,
                            type_source="Assessor override" if item["manual_type"] else "Automatic inference",
                            fingerprints=fingerprint_rows, observed_protocols=", ".join(sorted(protocols)))
                level, level_conf, level_evidence = self._suggest_level(role_index, item, fingerprint_rows, trusted_ips, protocols)
                item.update(suggested_level=level, level_confidence=level_conf, level_evidence=level_evidence,
                            purdue_source=item.get("purdue_source") or ("" if not item["purdue_level"] else "Assessor"))
                item.pop("source_ip_count", None)
                result.append(item)
            return result


    INDUSTRIAL_SERVER_PORTS = {502: "Modbus/TCP", 20000: "DNP3", 102: "S7comm", 44818: "EtherNet/IP", 2222: "EtherNet/IP I/O",
                               47808: "BACnet/IP", 4840: "OPC UA", 1883: "MQTT", 8883: "MQTT/TLS"}
    LEVEL1_ROLES = ("DNP3 outstation", "Siemens S7 controller", "Modbus device", "EtherNet/IP device", "BACnet device", "Profinet IO device", "Profinet device")
    LEVEL2_ROLES = ("DNP3 master", "S7 client (engineering/HMI/SCADA)", "Profinet IO controller", "Profinet controller/supervisor", "EtherNet/IP client (HMI/engineering)", "HMI")
    LEVEL1_ROLES = LEVEL1_ROLES + ("PLC (EtherNet/IP)", "Drive", "I/O adapter", "Safety I/O", "Motion controller", "Pneumatic valve terminal", "Communications adapter")

    def _suggest_level(self, role_index: dict, item: dict, fingerprints: list[dict], trusted_ips: list[str], protocols: set[str]) -> tuple[str, int, str]:
        """Suggest a Purdue level from protocol role, fingerprint role and device type. Returns (level, confidence, evidence)."""
        text = f"{item['manual_type']} {item.get('auto_type', '')}".lower()
        if item["classification"] == "Gateway/transit MAC" or any(k in text for k in ("gateway", "router", "switch", "network infrastructure", "access point")):
            return "", 0, "Network/boundary device spans levels; assign from drawings"
        served, spoke = {}, {}
        for ip in trusted_ips:
            for port, n in role_index["served"].get(ip, {}).items():
                served[self.INDUSTRIAL_SERVER_PORTS[port]] = served.get(self.INDUSTRIAL_SERVER_PORTS[port], 0) + n
            for port, n in role_index["spoke"].get(ip, {}).items():
                spoke[self.INDUSTRIAL_SERVER_PORTS[port]] = spoke.get(self.INDUSTRIAL_SERVER_PORTS[port], 0) + n
        roles = {f["value"] for f in fingerprints if f["field"] == "role"}
        if any(k in text for k in ("plc", "rtu", "controller", "drive", "safety", "outstation", "i/o", "instrument", "sensor", "actuator")) and item["manual_type"]:
            return "Level 1", 90, f"Assessor device type '{item['manual_type']}' indicates a control-level device"
        if roles & set(self.LEVEL1_ROLES):
            return "Level 1", 90, f"Responds as {', '.join(sorted(roles & set(self.LEVEL1_ROLES)))} (payload fingerprint)"
        if served and not spoke:
            return "Level 1", 85, f"Serves industrial protocol requests: {', '.join(sorted(served))}"
        if any(k in text for k in ("hmi", "scada", "engineering", "ews", "operator", "master")) and item["manual_type"]:
            return "Level 2", 85, f"Assessor device type '{item['manual_type']}' indicates supervisory control"
        if roles & set(self.LEVEL2_ROLES):
            return "Level 2", 85, f"Acts as {', '.join(sorted(roles & set(self.LEVEL2_ROLES)))} (payload fingerprint)"
        if spoke:
            if served:
                return "Level 2", 70, f"Both initiates ({', '.join(sorted(spoke))}) and serves ({', '.join(sorted(served))}) industrial protocols; gateway or SCADA server"
            return "Level 2", 75, f"Initiates industrial protocol requests: {', '.join(sorted(spoke))}"
        if any(k in text for k in ("historian", "domain controller", "jump", "server", "database", "patch", "antivirus", "backup")):
            return "Level 3", 65, "Device type indicates a site-operations server role"
        if any(k in text for k in ("firewall", "dmz")):
            return "Industrial DMZ", 70, "Device type indicates a boundary/DMZ device"
        enterprise = {"HTTPS", "HTTP", "DNS", "SMB", "RDP", "LDAP", "LDAPS", "SMTP", "NTP", "MS-RPC", "NETBIOS-NS"}
        if protocols and not (protocols & {"MODBUS-TCP", "DNP3", "S7COMM", "ETHERNET-IP", "ETHERNET-IP-IO", "BACNET-IP", "OPC-UA", "PROFINET-RT", "PROFINET-DCP"}):
            if any(k in text for k in ("computer", "workstation", "apple", "consumer", "iot", "camera", "phone", "endpoint", "embedded", "amazon")):
                return "Level 4", 50, f"No industrial protocol observed; enterprise/consumer protocols only ({', '.join(sorted(protocols & enterprise)) or 'IP'})"
        return "", 0, "Insufficient passive evidence to place; assign from drawings or walkdown"


    # ------------------------------------------------------------------ documented assets
    def add_documented_asset(self, values: dict) -> dict:
        """Create or update an asset from assessor entry / spreadsheet. A MAC links it to passive evidence; without one it is documented-only."""
        self._bump()
        import hashlib
        mac = str(values.get("mac", "")).strip().lower().replace("-", ":")
        if mac:
            compact = re.sub(r"[^0-9a-f]", "", mac)
            if len(compact) != 12:
                raise ValueError(f"Invalid MAC address: {values.get('mac')}")
            mac = ":".join(compact[i:i + 2] for i in range(0, 12, 2))
        name = str(values.get("name", "")).strip()
        if not mac and not name and not values.get("serial") and not values.get("asset_tag"):
            raise ValueError("A name, MAC, serial or asset tag is required")
        if not mac:
            seed = "|".join(str(values.get(k, "")).strip().lower() for k in ("name", "serial", "asset_tag", "location"))
            mac = "manual:" + hashlib.sha1(seed.encode()).hexdigest()[:10]
        now = iso_time()
        source = str(values.get("source", "")).strip() or "Spreadsheet import"
        if source not in self.ASSET_SOURCES:
            raise ValueError(f"Invalid source: {source}")
        fields = {}
        for key in self.EDITABLE_ASSET_FIELDS:
            src_key = {"vendor": "manufacturer", "manual_type": "device_type"}.get(key, key)
            if src_key in values and str(values[src_key]).strip():
                fields[key] = str(values[src_key]).strip()[:self.EDITABLE_ASSET_FIELDS[key]]
        fields["source"] = source
        if fields.get("purdue_level") and fields["purdue_level"] not in self.PURDUE_LEVELS:
            raise ValueError(f"Invalid purdue_level: {fields['purdue_level']} (use {', '.join(self.PURDUE_LEVELS)})")
        if fields.get("support_status") and fields["support_status"] not in self.SUPPORT_STATUSES:
            raise ValueError(f"Invalid support_status: {fields['support_status']}")
        if fields.get("backup_status") and fields["backup_status"] not in self.BACKUP_STATUSES:
            raise ValueError(f"Invalid backup_status: {fields['backup_status']}")
        with self.lock, self.connect() as db:
            alias = db.execute("SELECT asset_id FROM asset_aliases WHERE mac=?", (mac,)).fetchone()
            row = db.execute("SELECT id FROM assets WHERE mac=?", (mac,)).fetchone()
            if alias:
                asset_id = alias[0]
            elif row:
                asset_id = row[0]
            else:
                vendor = fields.pop("vendor", "") or (self.vendors.lookup(mac) if not mac.startswith("manual:") else "")
                cur = db.execute("INSERT INTO assets(mac,vendor,first_seen,last_seen,packets) VALUES(?,?,?,?,0)", (mac, vendor, now, now))
                asset_id = cur.lastrowid
            if fields:
                db.execute(f"UPDATE assets SET {','.join(f'{k}=?' for k in fields)} WHERE id=?", [*fields.values(), asset_id])
            if fields.get("purdue_level"):
                db.execute("UPDATE assets SET purdue_source='Assessor' WHERE id=?", (asset_id,))
            if name:
                self._name(db, asset_id, name, "Documented", 100, now)
            for ip in str(values.get("ip", "")).replace(";", ",").split(","):
                ip = ip.strip()
                if ip and endpoint_ip(ip):
                    self._ip(db, asset_id, ip, "Documented", 95, now)
        return next(item for item in self.assets() if item["id"] == asset_id)

    def asset_template_csv(self) -> bytes:
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(self.TEMPLATE_COLUMNS)
        writer.writerow(["PLC-101 Filter gallery", "00:1c:06:12:34:56", "10.10.1.10", "OT-0101", "Siemens", "6ES7 315-2EH14-0AB0", "S C-X1234567", "V3.2.7",
                         "PLC", "Filter gallery panel FP-3", "High", "Level 1", "Filtration cell", "Filter backwash control", "Loss of filtration; manual operation required",
                         "OT engineering", "Physical walkdown", "2014-06", "2021-10-01", "2025-10-01", "End of support", "No vendor patches available", "Backed up, untested", "2026-03-15", "Serial link to flow meter"])
        writer.writerow(["RTU-7 Lift station 7", "", "", "OT-0207", "Schweitzer", "SEL-3505", "", "", "RTU", "Lift station 7 cabinet", "Moderate", "Level 1",
                         "Remote sites", "Pump control and telemetry", "Overflow risk if telemetry lost", "Operations", "Drawing / documentation", "", "", "", "Unknown", "", "Unknown", "", "Radio backhaul; no Ethernet"])
        writer.writerow(["# Lines starting with # are ignored. Valid purdue_level: " + " | ".join(self.PURDUE_LEVELS) + ". Valid source: " + " | ".join(self.ASSET_SOURCES) +
                         ". Valid support_status: " + " | ".join(v for v in self.SUPPORT_STATUSES if v) + ". Valid backup_status: " + " | ".join(v for v in self.BACKUP_STATUSES if v) + ". criticality: Low | Moderate | High | Critical."])
        return out.getvalue().encode("utf-8-sig")

    def import_assets_csv(self, raw: bytes, default_source: str = "Spreadsheet import") -> dict:
        text = raw.decode("utf-8-sig", "replace")
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ValueError("CSV has no header row")
        headers = [h.strip().lower().replace(" ", "_") for h in reader.fieldnames]
        unknown = [h for h in headers if h and h not in self.TEMPLATE_COLUMNS and not h.startswith("#")]
        created = updated = 0
        errors = []
        with self.connect() as db:
            before = {r[0] for r in db.execute("SELECT mac FROM assets")}
        for number, row in enumerate(reader, start=2):
            values = {headers[i]: (v or "").strip() for i, v in enumerate(row.values()) if i < len(headers)}
            first = next(iter(values.values()), "")
            if not any(values.values()) or first.startswith("#"):
                continue
            values.setdefault("source", "")
            values["source"] = values["source"] or default_source
            try:
                item = self.add_documented_asset(values)
                if item["mac"] in before:
                    updated += 1
                else:
                    created += 1; before.add(item["mac"])
            except ValueError as exc:
                errors.append(f"Row {number}: {exc}")
        return {"created": created, "updated": updated, "errors": errors, "ignored_columns": unknown}

    def merge_assets(self, primary_id: int, secondary_id: int, note: str = "") -> dict:
        """Fold one identity into another (same chassis, second NIC). The secondary MAC becomes an alias of the primary."""
        self._bump()
        if primary_id == secondary_id:
            raise ValueError("Choose two different assets")
        with self.lock, self.connect() as db:
            prim = db.execute("SELECT * FROM assets WHERE id=?", (primary_id,)).fetchone()
            sec = db.execute("SELECT * FROM assets WHERE id=?", (secondary_id,)).fetchone()
            if not prim or not sec:
                raise ValueError("Asset does not exist")
            for table, key_cols in (("asset_ips", "ip,evidence"), ("asset_names", "name,evidence"), ("fingerprints", "field,value,evidence")):
                for r in db.execute(f"SELECT * FROM {table} WHERE asset_id=?", (secondary_id,)):
                    r = dict(r)
                    cols = [c for c in r if c != "asset_id"]
                    db.execute(f"INSERT OR IGNORE INTO {table}(asset_id,{','.join(cols)}) VALUES(?,{','.join('?' for _ in cols)})", (primary_id, *[r[c] for c in cols]))
            for r in db.execute("SELECT * FROM sightings WHERE asset_id=?", (secondary_id,)):
                r = dict(r)
                db.execute("""INSERT INTO sightings(asset_id,session_id,vlan,first_seen,last_seen,packets) VALUES(?,?,?,?,?,?)
                              ON CONFLICT(asset_id,session_id,vlan) DO UPDATE SET packets=sightings.packets+excluded.packets,
                              first_seen=min(sightings.first_seen,excluded.first_seen),last_seen=max(sightings.last_seen,excluded.last_seen)""",
                           (primary_id, r["session_id"], r["vlan"], r["first_seen"], r["last_seen"], r["packets"]))
            for col in ("vendor", "model", "serial", "firmware", "manual_type", "location", "criticality", "purdue_level", "zone", "process_function",
                        "safety_impact", "owner", "asset_tag", "install_date", "end_of_life", "end_of_support", "support_status", "patch_status", "backup_status", "last_backup"):
                if not prim[col] and sec[col]:
                    db.execute(f"UPDATE assets SET {col}=? WHERE id=?", (sec[col], primary_id))
            notes = (prim["notes"] + ("\n" if prim["notes"] and sec["notes"] else "") + sec["notes"]).strip()
            db.execute("UPDATE assets SET packets=packets+?,first_seen=min(first_seen,?),last_seen=max(last_seen,?),notes=? WHERE id=?",
                       (sec["packets"], sec["first_seen"], sec["last_seen"], notes, primary_id))
            if not sec["mac"].startswith("manual:"):
                db.execute("INSERT OR REPLACE INTO asset_aliases(mac,asset_id,note,created_at) VALUES(?,?,?,?)",
                           (sec["mac"], primary_id, note or f"Merged from asset {secondary_id}", iso_time()))
            for r in db.execute("SELECT mac FROM asset_aliases WHERE asset_id=?", (secondary_id,)):
                db.execute("UPDATE asset_aliases SET asset_id=? WHERE mac=?", (primary_id, r[0]))
            db.execute("DELETE FROM assets WHERE id=?", (secondary_id,))
        return next(item for item in self.assets() if item["id"] == primary_id)

    def delete_asset(self, asset_id: int):
        self._bump()
        with self.lock, self.connect() as db:
            row = db.execute("SELECT mac,packets FROM assets WHERE id=?", (asset_id,)).fetchone()
            if not row:
                raise ValueError("Asset does not exist")
            if row[1] and not row[0].startswith("manual:"):
                raise ValueError("Only documented-only assets (no passive evidence) can be deleted")
            db.execute("DELETE FROM assets WHERE id=?", (asset_id,))

    def update_asset(self, asset_id: int, values: dict) -> dict:
        self._bump()
        updates = {field: str(values[field]).strip()[:limit] for field, limit in self.EDITABLE_ASSET_FIELDS.items() if field in values}
        if not updates:
            raise ValueError("No editable asset fields were supplied")
        if updates.get("source") and updates["source"] not in self.ASSET_SOURCES:
            raise ValueError("Invalid asset source")
        with self.lock, self.connect() as db:
            if not db.execute("SELECT 1 FROM assets WHERE id=?", (asset_id,)).fetchone():
                raise ValueError("Asset does not exist")
            db.execute(f"UPDATE assets SET {','.join(f'{field}=?' for field in updates)} WHERE id=?", [*updates.values(), asset_id])
            if "purdue_level" in updates:
                source = "Suggested" if str(values.get("purdue_source", "")) == "Suggested" else "Assessor"
                db.execute("UPDATE assets SET purdue_source=? WHERE id=?", (source if updates["purdue_level"] else "", asset_id))
        return next(item for item in self.assets() if item["id"] == asset_id)

    def accept_suggested_levels(self, min_confidence: int = 50, overwrite: bool = False) -> int:
        """Apply suggested Purdue levels to assets that have none (or all, when overwrite)."""
        self._bump()
        count = 0
        with self.lock, self.connect() as db:
            for item in self.assets():
                if not item["physical_asset"] or not item["suggested_level"] or item["level_confidence"] < min_confidence:
                    continue
                if item["purdue_level"] and not (overwrite and item["purdue_source"] == "Suggested"):
                    continue
                db.execute("UPDATE assets SET purdue_level=?,purdue_source='Suggested' WHERE id=?", (item["suggested_level"], item["id"]))
                count += 1
        self._bump()
        return count

    def connections(self, limit: int = 2000) -> list[dict]:
        return self._cached(("connections", limit), lambda: self._connections(limit))

    def _connections(self, limit: int = 2000) -> list[dict]:
        with self.connect() as db:
            rows = db.execute("""
              SELECT c.*,s.collection_point,s.interface,s.assessment,s.site,
                (SELECT name FROM dns_names d WHERE d.ip=c.src_ip ORDER BY packets DESC LIMIT 1) src_name,
                (SELECT name FROM dns_names d WHERE d.ip=c.dst_ip ORDER BY packets DESC LIMIT 1) dst_name
              FROM connections c JOIN sessions s ON s.id=c.session_id
              ORDER BY c.packets DESC,c.id DESC LIMIT ?
            """, (limit,))
            result = []
            for row in rows:
                item = dict(row)
                item["src_port"], item["dst_port"] = ("" if item["src_port"] == -1 else item["src_port"]), ("" if item["dst_port"] == -1 else item["dst_port"])
                item["src_name"], item["dst_name"] = item["src_name"] or "", item["dst_name"] or ""
                result.append(item)
            return result

    PURDUE_LEVELS = ("Level 0", "Level 1", "Level 2", "Level 3", "Industrial DMZ", "Level 4", "Level 5")
    CONDUIT_DECISIONS = ("Unknown", "Approved", "Tolerated", "Unexpected")

    @classmethod
    def level_rank(cls, level: str) -> int:
        return cls.PURDUE_LEVELS.index(level) if level in cls.PURDUE_LEVELS else 99

    @staticmethod
    def endpoint_level(key: str, asset_levels: dict[int, str], infrastructure: set[int] | None = None) -> str:
        if key.startswith("asset:"):
            asset_id = int(key[6:])
            level = asset_levels.get(asset_id, "")
            if level:
                return level
            return "Network infrastructure" if infrastructure and asset_id in infrastructure else "Unassigned"
        if key.startswith("name:"):
            return "External"
        ip = key[3:]
        return "Unmapped local" if private_or_local_ip(ip) else "External"

    @classmethod
    def crossing_kind(cls, level_a: str, level_b: str) -> str:
        """Name the boundary a relationship crosses, or '' when it stays within a level."""
        if level_a == level_b:
            return ""
        if "Network infrastructure" in (level_a, level_b):
            other = level_b if level_a == "Network infrastructure" else level_a
            return "Infrastructure to external" if other == "External" else ""
        if "Unassigned" in (level_a, level_b):
            return "Involves unassigned asset"
        if "External" in (level_a, level_b):
            other = level_b if level_a == "External" else level_a
            return "OT to external/internet" if cls.level_rank(other) <= 4 else "Enterprise to external/internet"
        if "Unmapped local" in (level_a, level_b):
            return "Involves unmapped local endpoint"
        ranks = sorted((cls.level_rank(level_a), cls.level_rank(level_b)))
        if ranks[0] <= 3 and ranks[1] >= 5:
            return "OT to enterprise (bypasses industrial DMZ)"
        if ranks[0] <= 3 and ranks[1] == 4:
            return "OT to industrial DMZ"
        if ranks[0] == 4 and ranks[1] >= 5:
            return "Industrial DMZ to enterprise"
        lo, hi = sorted((level_a, level_b), key=cls.level_rank)
        return f"{lo} to {hi}"

    def conduits(self) -> dict[tuple[str, str], dict]:
        with self.connect() as db:
            return {(r["key_a"], r["key_b"]): dict(r) for r in db.execute("SELECT * FROM conduits")}

    def save_conduit(self, key_a: str, key_b: str, values: dict) -> dict:
        self._bump()
        decision = str(values.get("decision", "Unknown")).strip()
        if decision not in self.CONDUIT_DECISIONS:
            raise ValueError("Invalid conduit decision")
        key_a, key_b = sorted((str(key_a).strip(), str(key_b).strip()))
        if not key_a or not key_b:
            raise ValueError("Conduit endpoints are required")
        with self.lock, self.connect() as db:
            db.execute("""INSERT INTO conduits(key_a,key_b,decision,purpose,notes,updated_at) VALUES(?,?,?,?,?,?)
                          ON CONFLICT(key_a,key_b) DO UPDATE SET decision=excluded.decision,purpose=excluded.purpose,notes=excluded.notes,updated_at=excluded.updated_at""",
                       (key_a, key_b, decision, str(values.get("purpose", "")).strip()[:500], str(values.get("notes", "")).strip()[:2000], iso_time()))
            return dict(db.execute("SELECT * FROM conduits WHERE key_a=? AND key_b=?", (key_a, key_b)).fetchone())

    def relationships(self, limit: int = 1000, assets: list[dict] | None = None) -> list[dict]:
        if assets is not None and assets is not self._cache.get("assets", (None, None))[1]:
            return self._relationships(limit, assets)
        return self._cached(("relationships", limit), lambda: self._relationships(limit, None))

    def _relationships(self, limit: int = 1000, assets: list[dict] | None = None) -> list[dict]:
        assets = assets if assets is not None else self.assets()
        labels = {item["id"]: item["name"] or item["display_type"] or item["manufacturer"] or item["mac"] for item in assets}
        asset_levels = {item["id"]: item["purdue_level"] for item in assets}
        infrastructure = {item["id"] for item in assets if item["classification"] == "Gateway/transit MAC" or
                          any(k in (item["display_type"] or "").lower() for k in ("network infrastructure", "gateway", "router", "switch", "access point"))}
        ip_assets = {ip: item["id"] for item in assets for ip in item["ips"].split(",") if ip}
        conduits = self.conduits()
        groups = {}
        for flow in self.connections(100000):
            if flow["traffic_scope"] != "Unicast":
                continue
            if not endpoint_ip(flow["src_ip"]) or not endpoint_ip(flow["dst_ip"]):
                continue
            def endpoint(ip, name):
                asset_id = ip_assets.get(ip)
                if asset_id:
                    return (f"asset:{asset_id}", labels.get(asset_id, ip))
                if name and not private_or_local_ip(ip):
                    return (f"name:{name}", name)  # external services resolve to many IPs; merge on the name
                return (f"ip:{ip}", name or ip)
            src, dst = endpoint(flow["src_ip"], flow["src_name"]), endpoint(flow["dst_ip"], flow["dst_name"])
            if src[0] == dst[0]:
                continue
            ordered = sorted((src, dst), key=lambda value: value[0])
            mapped = sum(value[0].startswith("asset:") for value in ordered)
            category = "Local asset-to-asset" if mapped == 2 else "Asset-to-external/unknown" if mapped == 1 else "Unmapped unicast"
            key = (ordered[0][0], ordered[1][0], flow["collection_point"], flow["interface"], flow["vlan"])
            level_a, level_b = self.endpoint_level(ordered[0][0], asset_levels, infrastructure), self.endpoint_level(ordered[1][0], asset_levels, infrastructure)
            conduit = conduits.get((ordered[0][0], ordered[1][0]), {})
            group = groups.setdefault(key, {"endpoint_a": ordered[0][1], "endpoint_b": ordered[1][1], "protocols": set(),
                "key_a": ordered[0][0], "key_b": ordered[1][0], "level_a": level_a, "level_b": level_b,
                "crossing": self.crossing_kind(level_a, level_b),
                "decision": conduit.get("decision", "Unknown"), "purpose": conduit.get("purpose", ""),
                "category": category, "collection_point": flow["collection_point"], "interfaces": flow["interface"],
                "vlan": flow["vlan"], "flows": 0, "packets": 0, "bytes": 0, "ips": set(),
                "first_seen": flow["first_seen"], "last_seen": flow["last_seen"]})
            group["ips"].update(ip for ip in (flow["src_ip"], flow["dst_ip"]) if ip not in ip_assets)
            group["protocols"].add(flow["app_protocol"])
            group["flows"] += 1; group["packets"] += flow["packets"]; group["bytes"] += flow["bytes"]
            group["first_seen"] = min(group["first_seen"], flow["first_seen"]); group["last_seen"] = max(group["last_seen"], flow["last_seen"])
        result = []
        for group in groups.values():
            group["protocols"] = ", ".join(sorted(group["protocols"]))
            group["external_ips"] = len(group["ips"]); group["ips"] = ", ".join(sorted(group["ips"])[:12]); result.append(group)
        return sorted(result, key=lambda item: (-item["packets"], item["endpoint_a"], item["endpoint_b"]))[:limit]


    def zone_summary(self, assets: list[dict] | None = None, relationships: list[dict] | None = None) -> dict:
        if assets is None and relationships is None:
            return self._cached("zones", lambda: self._zone_summary(None, None))
        return self._zone_summary(assets, relationships)

    def _zone_summary(self, assets: list[dict] | None = None, relationships: list[dict] | None = None) -> dict:
        assets = assets if assets is not None else self.assets()
        relationships = relationships if relationships is not None else self.relationships(100000, assets)
        physical = [a for a in assets if a["physical_asset"]]
        is_infra = lambda a: not a["purdue_level"] and (a["classification"] == "Gateway/transit MAC" or any(k in (a["display_type"] or "").lower() for k in ("network infrastructure", "gateway", "router", "switch", "access point")))
        levels = {}
        for level in (*self.PURDUE_LEVELS, "Network infrastructure", "Unassigned"):
            members = [a for a in physical if (a["purdue_level"] or ("Network infrastructure" if is_infra(a) else "Unassigned")) == level]
            if members or level not in ("Unassigned", "Network infrastructure"):
                levels[level] = {"assets": len(members), "zones": sorted({a["zone"] for a in members if a["zone"]}),
                                 "names": [a["name"] or a["display_type"] or a["mac"] for a in members][:40]}
        pairs = {}
        for r in relationships:
            key = tuple(sorted((r["level_a"], r["level_b"]), key=lambda v: (self.level_rank(v), v)))
            item = pairs.setdefault(key, {"level_a": key[0], "level_b": key[1], "crossing": r["crossing"], "relationships": 0, "packets": 0,
                                          "protocols": set(), "decisions": {d: 0 for d in self.CONDUIT_DECISIONS}})
            item["relationships"] += 1; item["packets"] += r["packets"]
            item["protocols"].update(p for p in r["protocols"].split(", ") if p)
            item["decisions"][r["decision"]] = item["decisions"].get(r["decision"], 0) + 1
        crossings = []
        for item in pairs.values():
            item["protocols"] = ", ".join(sorted(item["protocols"]))
            crossings.append(item)
        crossings.sort(key=lambda i: (not i["crossing"], -i["packets"]))
        decisions = {d: sum(1 for r in relationships if r["decision"] == d) for d in self.CONDUIT_DECISIONS}
        return {"levels": levels, "assigned": sum(1 for a in physical if a["purdue_level"]), "physical": len(physical),
                "assigned_by_assessor": sum(1 for a in physical if a["purdue_level"] and a["purdue_source"] != "Suggested"),
                "assigned_from_suggestion": sum(1 for a in physical if a["purdue_level"] and a["purdue_source"] == "Suggested"),
                "suggestions_pending": sum(1 for a in physical if not a["purdue_level"] and a["suggested_level"]),
                "no_suggestion": sum(1 for a in physical if not a["purdue_level"] and not a["suggested_level"] and not is_infra(a)),
                "infrastructure": sum(1 for a in physical if is_infra(a)),
                "pairs": crossings, "crossings": [c for c in crossings if c["crossing"]], "decisions": decisions,
                "unreviewed_crossings": sum(1 for r in relationships if r["crossing"] and r["decision"] == "Unknown"),
                "unexpected": sum(1 for r in relationships if r["decision"] == "Unexpected")}

    def purdue_svg(self, assets: list[dict] | None = None, relationships: list[dict] | None = None) -> str:
        """Purdue band diagram: one band per level, assets as boxes, conduits aggregated per level pair."""
        from xml.sax.saxutils import escape as _e

        def _fit(s: str, n: int) -> str:
            """Truncate to at most n characters without splitting a word, appending an ellipsis."""
            s = s or ""
            if len(s) <= n:
                return s
            cut = s[:n - 1]
            if " " in cut:
                cut = cut[:cut.rfind(" ")]
            return (cut.rstrip() or s[:n - 1]) + "…"
        assets = assets if assets is not None else self.assets()
        relationships = relationships if relationships is not None else self.relationships(100000, assets)
        physical = [a for a in assets if a["physical_asset"]]
        order = ["Level 5", "Level 4", "Industrial DMZ", "Level 3", "Level 2", "Level 1", "Level 0", "Network infrastructure", "Unassigned"]
        is_infra = lambda a: not a["purdue_level"] and (a["classification"] == "Gateway/transit MAC" or any(k in (a["display_type"] or "").lower() for k in ("network infrastructure", "gateway", "router", "switch", "access point")))
        band_of = lambda a: a["purdue_level"] or ("Network infrastructure" if is_infra(a) else "Unassigned")
        externals = [r for r in relationships if "External" in (r["level_a"], r["level_b"])]
        bands = [lv for lv in order if any(band_of(a) == lv for a in physical) or lv not in ("Unassigned", "Network infrastructure")]
        if externals:
            bands.insert(0, "External")
        width, pad, box_w, box_h, label_w = 1600, 16, 160, 40, 130
        colors = {"Approved": "#18794e", "Tolerated": "#9a6700", "Unexpected": "#b42318", "Unknown": "#617181"}
        fills = {"External": "#f3e8ff", "Level 5": "#e9eff3", "Level 4": "#e9eff3", "Industrial DMZ": "#fff7d6", "Level 3": "#e3f0f5",
                 "Level 2": "#e3f0f5", "Level 1": "#e3f5ea", "Level 0": "#e3f5ea", "Network infrastructure": "#f3f6f8", "Unassigned": "#fde8e6"}
        # Conduits are aggregated per level pair, numbered in the same order as the zone-pair table (crossings
        # first, then by packets) so "#3" on the diagram is row 3 in the table, in the report and in the export.
        pairs = {}
        for r in relationships:
            a, b = r["level_a"], r["level_b"]
            if a not in bands or b not in bands or a == b:
                continue
            key = tuple(sorted((a, b), key=lambda v: (self.level_rank(v), v)))
            item = pairs.setdefault(key, {"n": 0, "packets": 0, "crossing": r["crossing"], "decisions": set(), "protocols": set()})
            item["n"] += 1; item["packets"] += r["packets"]; item["decisions"].add(r["decision"])
            item["protocols"].update(p for p in r["protocols"].split(", ") if p)
        ordered_pairs = sorted(pairs.items(), key=lambda kv: (not kv[1]["crossing"], -kv[1]["packets"], kv[0]))
        legend_rows = len(ordered_pairs)
        # Split the width between asset cards (left) and conduit lines (right) by what each actually needs:
        # every conduit gets a 56px slot, the cards get the rest. A band with more members than fit in one
        # row gets a second row (which makes every band taller) before folding into "+N more".
        n_pairs = len(ordered_pairs)
        conduit_w = max(140, min(int(width * 0.45), n_pairs * 56 + 70))
        card_area_right = width - pad - conduit_w
        cols = max(1, (card_area_right - (pad + label_w)) // (box_w + 10))
        members_of = {lv: ([a for a in physical if band_of(a) == lv] if lv != "External" else []) for lv in bands}
        band_hs = {lv: 142 if len(members_of[lv]) > cols else 96 for lv in bands}  # only a band that needs two rows gets taller
        bands_h = sum(band_hs.values())
        height = bands_h + pad * 2 + 30 + 22 + legend_rows * 15
        out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" font-family="system-ui, sans-serif" font-size="12">',
               f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
               f'<text x="{pad}" y="{pad + 4}" font-size="16" font-weight="700" fill="#112d3a">Purdue zones and observed conduits</text>']
        y_of = {}
        y = pad + 30
        for lv in bands:
            band_h = band_hs[lv]
            y_of[lv] = y
            out.append(f'<rect x="{pad}" y="{y}" width="{width - 2 * pad}" height="{band_h - 6}" rx="8" fill="{fills.get(lv, "#eee")}" stroke="#d9e1e7"/>')
            out.append(f'<line x1="{pad}" y1="{y + band_h - 6}" x2="{width - pad}" y2="{y + band_h - 6}" stroke="#ffffff" stroke-width="6"/>')
            out.append(f'<text x="{pad + 10}" y="{y + 18}" font-weight="700" fill="#16212b">{_e(lv)}</text>')
            members = members_of[lv]
            capacity = cols * (2 if band_h > 96 else 1)
            for idx, a in enumerate(members):
                if idx == capacity - 1 and len(members) > capacity:
                    # last slot becomes the overflow marker so the count is never hidden
                    cx, cy = pad + label_w + (idx % cols) * (box_w + 10), y + 26 + (idx // cols) * (box_h + 6)
                    out.append(f'<text x="{cx}" y="{cy + 24}" fill="#617181">+{len(members) - idx} more</text>')
                    break
                cx, cy = pad + label_w + (idx % cols) * (box_w + 10), y + 26 + (idx // cols) * (box_h + 6)
                label = _fit(a["name"] or a["display_type"] or a["mac"], 20)
                sub = _fit(a["display_type"] if a["name"] else (a["ips"].split(",")[0] or a["mac"]), 26)
                # hover text travels with the SVG (works in the exported file too); the app also opens the asset on click
                detail = [a["name"] or a["display_type"] or a["mac"], a["display_type"] or "",
                          " ".join(v for v in (a.get("manufacturer"), a.get("model")) if v),
                          f"IP {a['ips']}" if a.get("ips") else "", f"MAC {a['mac']}" if a.get("mac") else "",
                          f"Firmware {a['firmware']}" if a.get("firmware") else "",
                          f"Criticality {a['criticality']}" if a.get("criticality") else "",
                          f"Location {a['location']}" if a.get("location") else "", f"Zone {a['zone']}" if a.get("zone") else "",
                          f"Function {a['process_function']}" if a.get("process_function") else "",
                          f"Protocols {a['observed_protocols']}" if a.get("observed_protocols") else "",
                          f"Support {a['support_status']}" if a.get("support_status") else ""]
                out.append(f'<g class="node" data-asset="{a["id"]}"><title>{_e(chr(10).join(d for d in detail if d))}</title>')
                out.append(f'<rect x="{cx}" y="{cy}" width="{box_w}" height="{box_h}" rx="5" fill="#ffffff" stroke="#bac7d0"/>')
                out.append(f'<text x="{cx + 8}" y="{cy + 16}" font-weight="700" fill="#16212b">{_e(label)}</text>')
                out.append(f'<text x="{cx + 8}" y="{cy + 32}" fill="#617181" font-size="10">{_e(sub)}</text></g>')
            if lv == "External":
                out.append(f'<text x="{pad + label_w}" y="{y + 50}" fill="#617181">{len({r["endpoint_a"] if r["level_a"] == "External" else r["endpoint_b"] for r in externals})} external endpoint(s) observed</text>')
            y += band_h
        # Conduit lines. Each level pair gets its own vertical slot in the right-hand part of the diagram
        # (no two lines share an x), its two end dots sit INSIDE the bands they join (not on the boundary
        # between bands), the stretch through any band in between is drawn thin and faded so it reads as
        # "passing through", and a numbered badge at the midpoint ties the line to the table row and legend.
        x0, x1 = card_area_right + 40, width - pad - 30
        step = min(110, (x1 - x0) / max(1, n_pairs - 1)) if n_pairs > 1 else 0
        stub = 16  # how far inside a band the end dot sits
        for i, (key, item) in enumerate(ordered_pairs):
            hi, lo = sorted(key, key=lambda v: bands.index(v))  # hi = drawn higher on the page
            y_top, y_bot = y_of[hi] + band_hs[hi] - 6 - stub, y_of[lo] + stub
            edge_top, edge_bot = y_of[hi] + band_hs[hi] - 6, y_of[lo]
            color = colors["Unexpected"] if "Unexpected" in item["decisions"] else colors["Unknown"] if "Unknown" in item["decisions"] else colors["Tolerated"] if "Tolerated" in item["decisions"] else colors["Approved"]
            dash = ' stroke-dasharray="6,4"' if "Unknown" in item["decisions"] else ""
            x = round(x1 - i * step, 1)
            pair_id = f'{key[0]}|{key[1]}'
            num = i + 1
            out.append(f'<g class="conduit" data-pair="{_e(pair_id)}" data-n="{num}" style="cursor:pointer">')
            out.append(f'<title>#{num} {_e(key[0])} ↔ {_e(key[1])}: {item["n"]} relationship(s) · {_e(", ".join(sorted(item["protocols"])))}</title>')
            # pass-through stretch (thin, faded) — only exists when the two bands aren't adjacent
            if edge_bot > edge_top:
                out.append(f'<line class="through" x1="{x}" y1="{edge_top}" x2="{x}" y2="{edge_bot}" stroke="{color}" stroke-width="2" stroke-opacity="0.35"{dash}/>')
            # anchored stubs inside the two bands (bold)
            out.append(f'<line class="stub" x1="{x}" y1="{y_top}" x2="{x}" y2="{edge_top}" stroke="{color}" stroke-width="4"{dash}/>')
            out.append(f'<line class="stub" x1="{x}" y1="{edge_bot}" x2="{x}" y2="{y_bot}" stroke="{color}" stroke-width="4"{dash}/>')
            out.append(f'<circle class="dot" cx="{x}" cy="{y_top}" r="5" fill="{color}" stroke="#ffffff" stroke-width="1.5"/>')
            out.append(f'<circle class="dot" cx="{x}" cy="{y_bot}" r="5" fill="{color}" stroke="#ffffff" stroke-width="1.5"/>')
            # numbered badge at the midpoint
            my = (y_top + y_bot) / 2
            out.append(f'<circle class="badge" cx="{x}" cy="{my}" r="10" fill="#ffffff" stroke="{color}" stroke-width="2"/>')
            out.append(f'<text x="{x}" y="{my + 4}" text-anchor="middle" font-size="11" font-weight="700" fill="{color}">{num}</text>')
            out.append('</g>')
        # legend: colour key, then one numbered row per conduit so the exported SVG stands on its own
        ly = pad + 30 + bands_h + 6
        for i, (name, color) in enumerate(colors.items()):
            out.append(f'<rect x="{pad + i * 120}" y="{ly - 10}" width="12" height="12" fill="{color}"/><text x="{pad + i * 120 + 16}" y="{ly}" fill="#16212b">{name}</text>')
        out.append(f'<text x="{pad + 500}" y="{ly}" fill="#617181">Dashed = not yet reviewed. Bold ends mark the two bands a conduit joins; the faint stretch only passes through.</text>')
        for i, (key, item) in enumerate(ordered_pairs):
            color = colors["Unexpected"] if "Unexpected" in item["decisions"] else colors["Unknown"] if "Unknown" in item["decisions"] else colors["Tolerated"] if "Tolerated" in item["decisions"] else colors["Approved"]
            ry = ly + 20 + i * 15
            out.append(f'<circle cx="{pad + 8}" cy="{ry - 4}" r="7" fill="#ffffff" stroke="{color}" stroke-width="1.5"/><text x="{pad + 8}" y="{ry - 1}" text-anchor="middle" font-size="9" font-weight="700" fill="{color}">{i + 1}</text>')
            hi, lo = sorted(key, key=lambda v: bands.index(v))
            out.append(f'<text x="{pad + 22}" y="{ry}" font-size="11" fill="#16212b">{_e(hi)} → {_e(lo)}: {item["n"]} relationship(s) · <tspan fill="#617181">{_e(_fit(", ".join(sorted(item["protocols"])), 70))}</tspan></text>')
        out.append("</svg>")
        return "".join(out)

    def discovery_traffic(self, limit: int = 1000) -> list[dict]:
        return self._cached(("discovery", limit), lambda: self._discovery_traffic(limit))

    def _discovery_traffic(self, limit: int = 1000) -> list[dict]:
        groups = {}
        for flow in self.connections(100000):
            if flow["traffic_scope"] != "Broadcast/multicast":
                continue
            key = (flow["src_ip"], flow["dst_ip"], flow["app_protocol"], flow["collection_point"], flow["interface"], flow["vlan"])
            group = groups.setdefault(key, {"source": flow["src_name"] or flow["src_ip"],
                "destination": flow["dst_name"] or flow["dst_ip"], "protocol": flow["app_protocol"],
                "collection_point": flow["collection_point"], "interface": flow["interface"], "vlan": flow["vlan"],
                "flows": 0, "packets": 0, "bytes": 0})
            group["flows"] += 1
            group["packets"] += flow["packets"]
            group["bytes"] += flow["bytes"]
        return sorted(groups.values(), key=lambda item: (-item["packets"], item["source"], item["destination"]))[:limit]

    def dashboard(self) -> dict:
        return self._cached("dashboard", self._dashboard)

    def _dashboard(self) -> dict:
        with self.connect() as db:
            base = dict(db.execute("SELECT (SELECT count(*) FROM connections) flows,(SELECT count(*) FROM sessions) sessions,COALESCE((SELECT sum(packets) FROM sessions),0) packets").fetchone())
        assets = self.assets()
        base.update(assets=sum(1 for item in assets if item["physical_asset"]), identities=len(assets),
                    relationships=len(self.relationships(100000, assets)), discovery_groups=len(self.discovery_traffic(100000)))
        return base

    def sessions(self) -> list[dict]:
        with self.connect() as db:
            rows = [dict(row) for row in db.execute("SELECT * FROM sessions ORDER BY id DESC")]
        for row in rows:
            row["duration_seconds"] = duration_seconds(row["started_at"], row["ended_at"])
            row["duration"] = format_duration(row["duration_seconds"])
        return rows

    def coverage(self) -> dict:
        """Summarise visibility across all collection points, not just the latest session."""
        with self.connect() as db:
            rows = [dict(r) for r in db.execute("SELECT * FROM sessions ORDER BY id")]
        if not rows:
            return {"level": "none", "message": "No collection has been performed.", "points": []}
        points: dict[str, dict] = {}
        for r in rows:
            p = points.setdefault(r["collection_point"], {"point": r["collection_point"], "sessions": 0, "packets": 0, "third_party": 0, "pcap": False, "access": set()})
            p["sessions"] += 1; p["packets"] += r["packets"]; p["third_party"] += r["third_party_unicast"]
            p["pcap"] = p["pcap"] or r["source_type"] == "pcap"; p["access"].add(r["access_method"])
        summary = []
        for p in points.values():
            p["access"] = ", ".join(sorted(p["access"]))
            p["level"] = ("unknown" if p["pcap"] else "likely-mirror" if p["third_party"] >= 10 else "limited" if p["packets"] else "none")
            summary.append(p)
        mirror = [p for p in summary if p["level"] == "likely-mirror"]
        limited = [p for p in summary if p["level"] == "limited"]
        empty = [p for p in summary if p["level"] == "none"]
        pcap = [p for p in summary if p["level"] == "unknown"]
        if len(summary) == 1:
            p = summary[0]
            if p["level"] == "unknown":
                return {"level": "unknown", "message": "Imported PCAP visibility depends on its original capture point.", "points": summary}
            if p["level"] == "likely-mirror":
                return {"level": "likely-mirror", "message": f"Third-party unicast traffic observed ({p['third_party']} frames). Mirror/TAP visibility is likely, but coverage still requires validation.", "points": summary}
            if p["level"] == "limited":
                return {"level": "limited", "message": "No meaningful third-party unicast traffic observed. This appears to be an ordinary access port or limited feed; inventory is incomplete.", "points": summary}
            return {"level": "none", "message": "No packets observed. Verify the interface, cabling and capture point.", "points": summary}
        parts = []
        if mirror: parts.append(f"mirror/TAP visibility likely at {', '.join(p['point'] for p in mirror)}")
        if limited: parts.append(f"access-port visibility only at {', '.join(p['point'] for p in limited)}")
        if pcap: parts.append(f"imported PCAP at {', '.join(p['point'] for p in pcap)}")
        if empty: parts.append(f"no packets at {', '.join(p['point'] for p in empty)}")
        level = "mixed" if mirror and (limited or empty or pcap) else "likely-mirror" if mirror else "limited" if limited else "unknown" if pcap else "none"
        return {"level": level, "message": f"{len(summary)} collection points: " + "; ".join(parts) + ". Coverage must be judged per network leg.", "points": summary}

    def csv_export(self, kind: str) -> bytes:
        records = (self.assets() if kind == "assets" else self.relationships(100000) if kind == "relationships"
                   else self.discovery_traffic(100000) if kind == "discovery" else self.connections(100000))
        if kind == "assets":
            for item in records:
                item["fingerprints"] = json.dumps(item["fingerprints"], separators=(",", ":"))
                item["ip_evidence"] = json.dumps(item["ip_evidence"], separators=(",", ":"))
        output = io.StringIO()
        if records:
            writer = csv.DictWriter(output, fieldnames=list(records[0].keys()), extrasaction="ignore"); writer.writeheader(); writer.writerows(records)
        return output.getvalue().encode("utf-8")

    def json_export(self) -> bytes:
        assets = self.assets_with_exposure()
        return json.dumps({"generated_at": iso_time(), "summary": self.dashboard(), "sessions": self.sessions(), "assets": assets,
                           "relationships": self.relationships(100000, self.assets()), "discovery_traffic": self.discovery_traffic(100000),
                           "flows": self.connections(100000), "sites": self.sites(), "findings": self.findings(), "zones": self.zone_summary(assets)}, indent=2).encode("utf-8")

    def vendor_status(self) -> dict:
        return {"entries": len(self.vendors.prefixes), "available": bool(self.vendors.prefixes)}


    # ------------------------------------------------------------------ site validation
    CHECKLIST_ITEMS = [
        ("facility_function", "Facility type and operational function", "What the site does, its process criticality and who operates it"),
        ("ingress_egress", "Network ingress and egress points", "Every physical and logical path in or out: WAN, fibre, radio, cellular, vendor links, dial-up"),
        ("asset_categories", "OT asset categories and managed switching", "SCADA servers, HMIs, EWS, historians, PLCs/RTUs/drives, safety systems, gateways, converters, radios, modems; managed vs unmanaged switching"),
        ("scada_historian", "SCADA and historian communications", "Masters, redundancy, polling paths, historian collection and replication, access paths"),
        ("remote_access", "Remote-access and vendor-support paths", "Jump hosts, VPNs, vendor tools, cellular modems, dormant accounts, bypass mechanisms"),
        ("telemetry", "Telemetry and field-communication paths", "Radio, cellular, serial, leased line and remote-site backhaul"),
        ("documentation", "Site documentation and deviations", "Drawings, equipment lists, switch and firewall exports obtained; deviations from expected architecture noted"),
        ("interviews", "Operator and engineer interviews", "Interviews conducted with operations, OT engineering, IT/network and vendor contacts"),
        ("config_review", "Configuration and log review", "Firewall rules, switch configs, historian and alarm logs, NetFlow, SPAN/TAP availability reviewed"),
        ("walkdown", "Physical walkdown", "Panels, enclosures, physical security, labelling and unmanaged connections observed in person"),
        ("safety", "Safety and access controls followed", "Site induction, PPE, escort and non-intrusive assessment constraints recorded"),
    ]
    CHECKLIST_STATUSES = ("Not started", "In progress", "Complete", "Not applicable")
    LEG_EVIDENCE_SOURCES = ("None yet", "Configured SPAN/mirror", "Network TAP", "Unconfirmed access port", "Customer PCAP",
                            "NetFlow / firewall logs", "Switch tables / ARP", "Drawings and interviews only")
    LEG_STATUSES = ("Planned", "Collected", "Partial", "Not accessible", "Out of scope")
    SITE_FIELDS = {"assessment": 200, "name": 200, "facility_type": 200, "operational_function": 500, "contacts": 500,
                   "walkdown_date": 40, "documentation": 1000, "deviations": 2000, "notes": 4000}
    LEG_FIELDS = {"name": 200, "description": 500, "purdue_level": 40, "evidence_source": 60, "collection_point": 200,
                  "status": 40, "time_window": 200, "exclusions": 1000, "limitations": 2000, "notes": 4000}

    def save_site(self, values: dict) -> dict:
        self._bump()
        updates = {f: str(values.get(f, "")).strip()[:n] for f, n in self.SITE_FIELDS.items() if f in values}
        site_id = values.get("id")
        now = iso_time()
        with self.lock, self.connect() as db:
            if site_id:
                if not updates:
                    raise ValueError("No site fields were supplied")
                sets = ",".join(f"{f}=?" for f in updates)
                db.execute(f"UPDATE sites SET {sets},updated_at=? WHERE id=?", (*updates.values(), now, int(site_id)))
            else:
                if not updates.get("name"):
                    raise ValueError("Site name is required")
                updates.setdefault("assessment", "")
                cols = ",".join(updates)
                cur = db.execute(f"INSERT INTO sites({cols},created_at,updated_at) VALUES({','.join('?' for _ in updates)},?,?)", (*updates.values(), now, now))
                site_id = cur.lastrowid
                for key, _label, _desc in self.CHECKLIST_ITEMS:
                    db.execute("INSERT OR IGNORE INTO site_checklist(site_id,item,updated_at) VALUES(?,?,?)", (site_id, key, now))
        return self.site(int(site_id))

    def delete_site(self, site_id: int):
        self._bump()
        with self.lock, self.connect() as db:
            db.execute("DELETE FROM sites WHERE id=?", (site_id,))

    def save_checklist_item(self, site_id: int, item: str, values: dict) -> dict:
        self._bump()
        if item not in {key for key, _l, _d in self.CHECKLIST_ITEMS}:
            raise ValueError("Unknown checklist item")
        status = str(values.get("status", "Not started")).strip()
        if status not in self.CHECKLIST_STATUSES:
            raise ValueError("Invalid checklist status")
        with self.lock, self.connect() as db:
            db.execute("""INSERT INTO site_checklist(site_id,item,status,evidence,notes,updated_at) VALUES(?,?,?,?,?,?)
                          ON CONFLICT(site_id,item) DO UPDATE SET status=excluded.status,evidence=excluded.evidence,notes=excluded.notes,updated_at=excluded.updated_at""",
                       (site_id, item, status, str(values.get("evidence", "")).strip()[:1000], str(values.get("notes", "")).strip()[:2000], iso_time()))
        return self.site(site_id)

    def save_leg(self, site_id: int, values: dict) -> dict:
        self._bump()
        updates = {f: str(values.get(f, "")).strip()[:n] for f, n in self.LEG_FIELDS.items() if f in values}
        if "evidence_source" in updates and updates["evidence_source"] not in self.LEG_EVIDENCE_SOURCES:
            raise ValueError("Invalid evidence source")
        if "status" in updates and updates["status"] not in self.LEG_STATUSES:
            raise ValueError("Invalid leg status")
        leg_id = values.get("id")
        now = iso_time()
        with self.lock, self.connect() as db:
            if not db.execute("SELECT 1 FROM sites WHERE id=?", (site_id,)).fetchone():
                raise ValueError("Site does not exist")
            if leg_id:
                sets = ",".join(f"{f}=?" for f in updates)
                db.execute(f"UPDATE network_legs SET {sets},updated_at=? WHERE id=? AND site_id=?", (*updates.values(), now, int(leg_id), site_id))
            else:
                if not updates.get("name"):
                    raise ValueError("Network leg name is required")
                cols = ",".join(updates)
                db.execute(f"INSERT INTO network_legs(site_id,{cols},created_at,updated_at) VALUES(?,{','.join('?' for _ in updates)},?,?)", (site_id, *updates.values(), now, now))
        return self.site(site_id)

    def delete_leg(self, leg_id: int):
        self._bump()
        with self.lock, self.connect() as db:
            db.execute("DELETE FROM network_legs WHERE id=?", (leg_id,))

    def _leg_coverage(self, db, site_name: str, leg: dict) -> dict:
        """Roll up sessions whose collection point matches this leg (and site when recorded)."""
        if not leg["collection_point"]:
            return {"sessions": 0, "packets": 0, "third_party_unicast": 0, "duration_seconds": 0, "assets_seen": 0, "signal": "No collection point linked"}
        rows = [dict(r) for r in db.execute("SELECT * FROM sessions WHERE collection_point=? AND (site=? OR ?='')", (leg["collection_point"], site_name, site_name))]
        if not rows:
            return {"sessions": 0, "packets": 0, "third_party_unicast": 0, "duration_seconds": 0, "assets_seen": 0, "signal": "No sessions recorded for this collection point"}
        ids = [r["id"] for r in rows]
        assets_seen = db.execute(f"SELECT count(DISTINCT asset_id) FROM sightings WHERE session_id IN ({','.join('?' for _ in ids)})", ids).fetchone()[0]
        packets = sum(r["packets"] for r in rows); third = sum(r["third_party_unicast"] for r in rows)
        duration = sum((duration_seconds(r["started_at"], r["ended_at"]) or 0) for r in rows)
        signal = ("Third-party unicast observed; mirror/TAP visibility likely" if third >= 10 else
                  "Local and broadcast traffic only; access-port visibility" if packets else "Sessions recorded but no packets")
        return {"sessions": len(rows), "packets": packets, "third_party_unicast": third, "duration_seconds": duration,
                "duration": format_duration(duration), "assets_seen": assets_seen, "signal": signal}

    def site(self, site_id: int) -> dict:
        with self.connect() as db:
            row = db.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
            if not row:
                raise ValueError("Site does not exist")
            item = dict(row)
            saved = {r["item"]: dict(r) for r in db.execute("SELECT * FROM site_checklist WHERE site_id=?", (site_id,))}
            item["checklist"] = [{"item": key, "label": label, "description": desc, "status": saved.get(key, {}).get("status", "Not started"),
                                  "evidence": saved.get(key, {}).get("evidence", ""), "notes": saved.get(key, {}).get("notes", ""),
                                  "updated_at": saved.get(key, {}).get("updated_at", "")} for key, label, desc in self.CHECKLIST_ITEMS]
            done = sum(1 for c in item["checklist"] if c["status"] in ("Complete", "Not applicable"))
            item["checklist_complete"] = done; item["checklist_total"] = len(item["checklist"])
            legs = [dict(r) for r in db.execute("SELECT * FROM network_legs WHERE site_id=? ORDER BY id", (site_id,))]
            for leg in legs:
                leg["coverage"] = self._leg_coverage(db, item["name"], leg)
            item["legs"] = legs
            item["legs_with_evidence"] = sum(1 for leg in legs if leg["evidence_source"] != "None yet" and leg["status"] in ("Collected", "Partial"))
            return item

    def sites(self) -> list[dict]:
        with self.connect() as db:
            ids = [r[0] for r in db.execute("SELECT id FROM sites ORDER BY assessment,name")]
        return [self.site(i) for i in ids]

    def known_collection_points(self) -> list[str]:
        with self.connect() as db:
            return [r[0] for r in db.execute("SELECT DISTINCT collection_point FROM sessions ORDER BY collection_point")]


    # ------------------------------------------------------------------ findings register
    FINDING_KINDS = ("Control deficiency", "Evidence gap", "Improvement opportunity", "Positive observation")
    FINDING_RATINGS = ("Critical", "High priority", "Moderate", "Low", "Informational", "Positive")
    FINDING_CONFIDENCE = ("High", "Moderate", "Low")
    FINDING_HORIZONS = ("Immediate / quick win", "30-90 days", "3-12 months", "Strategic", "Not applicable")
    FINDING_STATUSES = ("Draft", "Validated", "Accepted", "Rejected", "Closed")
    FINDING_FIELDS = {"ref": 20, "title": 200, "kind": 40, "rating": 40, "confidence": 20, "owner": 200, "condition": 4000,
                      "evidence": 4000, "impact": 4000, "recommendation": 4000, "closure": 4000, "horizon": 40,
                      "status": 20, "site": 200, "assets": 1000, "source": 60, "iec62443": 500, "attack": 500, "draft_key": 120}
    LINK_KINDS = ("relationship", "asset", "pair")

    def save_finding(self, values: dict) -> dict:
        self._bump()
        updates = {f: str(values.get(f, "")).strip()[:n] for f, n in self.FINDING_FIELDS.items() if f in values}
        for field, allowed in (("kind", self.FINDING_KINDS), ("rating", self.FINDING_RATINGS), ("confidence", self.FINDING_CONFIDENCE),
                               ("horizon", self.FINDING_HORIZONS), ("status", self.FINDING_STATUSES)):
            if field in updates and updates[field] not in allowed:
                raise ValueError(f"Invalid {field}: {updates[field]}")
        finding_id = values.get("id")
        now = iso_time()
        with self.lock, self.connect() as db:
            if finding_id:
                if not updates and "links" not in values:
                    raise ValueError("No finding fields were supplied")
                if updates:
                    sets = ",".join(f"{f}=?" for f in updates)
                    db.execute(f"UPDATE findings SET {sets},updated_at=? WHERE id=?", (*updates.values(), now, int(finding_id)))
            else:
                if not updates.get("title"):
                    raise ValueError("Finding title is required")
                if not updates.get("ref"):
                    updates["ref"] = self._next_ref(db, updates.get("kind", "Evidence gap"))
                cols = ",".join(updates)
                cur = db.execute(f"INSERT INTO findings({cols},created_at,updated_at) VALUES({','.join('?' for _ in updates)},?,?)", (*updates.values(), now, now))
                finding_id = cur.lastrowid
            if "links" in values:
                self._replace_links(db, int(finding_id), values["links"] or [])
            return self._finding_row(db, int(finding_id))

    @staticmethod
    def _next_ref(db, kind: str) -> str:
        prefix = "POS" if kind == "Positive observation" else "FND" if kind == "Control deficiency" else "OBS"
        existing = [row[0] for row in db.execute("SELECT ref FROM findings WHERE ref LIKE ?", (prefix + "-%",))]
        numbers = [int(r.split("-")[1]) for r in existing if r.split("-")[-1].isdigit()]
        return f"{prefix}-{(max(numbers) + 1) if numbers else 1:02d}"

    def delete_finding(self, finding_id: int):
        self._bump()
        with self.lock, self.connect() as db:
            db.execute("DELETE FROM findings WHERE id=?", (finding_id,))

    def findings(self) -> list[dict]:
        order = {r: i for i, r in enumerate(self.FINDING_RATINGS)}
        with self.connect() as db:
            rows = [dict(r) for r in db.execute("SELECT * FROM findings")]
            links: dict[int, list] = {}
            for r in db.execute("SELECT finding_id,kind,key FROM finding_links ORDER BY kind,key"):
                links.setdefault(r[0], []).append({"kind": r[1], "key": r[2]})
        for f in rows:
            f["links"] = links.get(f["id"], [])
        return sorted(rows, key=lambda f: (order.get(f["rating"], 99), f["ref"]))

    # ---- finding ↔ evidence links --------------------------------------------------------
    # kind 'relationship': key "key_a|key_b" (the conduit endpoint pair, as sorted by save_conduit)
    # kind 'asset':        key = asset id as text
    # kind 'pair':         key "Level A|Level B" (zone pair, ordered by level_rank — see pair_key)
    @classmethod
    def pair_key(cls, level_a: str, level_b: str) -> str:
        lo, hi = sorted((level_a or "", level_b or ""), key=lambda v: (cls.level_rank(v), v))
        return f"{lo}|{hi}"

    @staticmethod
    def relationship_key(key_a: str, key_b: str) -> str:
        return "|".join(sorted((str(key_a), str(key_b))))

    def _normalise_link(self, link: dict) -> tuple[str, str]:
        kind = str(link.get("kind", "")).strip()
        key = str(link.get("key", "")).strip()[:300]
        if kind not in self.LINK_KINDS or not key:
            raise ValueError(f"Invalid finding link: {link!r}")
        if kind == "pair" and "|" in key:
            key = self.pair_key(*key.split("|", 1))
        if kind == "relationship" and "|" in key:
            key = self.relationship_key(*key.split("|", 1))
        return kind, key

    def _replace_links(self, db, finding_id: int, links: list[dict]):
        pairs = {self._normalise_link(l) for l in links}
        db.execute("DELETE FROM finding_links WHERE finding_id=?", (finding_id,))
        db.executemany("INSERT OR IGNORE INTO finding_links(finding_id,kind,key) VALUES(?,?,?)",
                       [(finding_id, k, v) for k, v in sorted(pairs)])

    def _finding_row(self, db, finding_id: int) -> dict:
        row = db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise ValueError("Finding does not exist")
        item = dict(row)
        item["links"] = [{"kind": r[0], "key": r[1]} for r in db.execute("SELECT kind,key FROM finding_links WHERE finding_id=? ORDER BY kind,key", (finding_id,))]
        return item

    def link_finding(self, finding_id: int, kind: str, key: str) -> dict:
        self._bump()
        kind, key = self._normalise_link({"kind": kind, "key": key})
        with self.lock, self.connect() as db:
            if not db.execute("SELECT 1 FROM findings WHERE id=?", (finding_id,)).fetchone():
                raise ValueError("Finding does not exist")
            db.execute("INSERT OR IGNORE INTO finding_links(finding_id,kind,key) VALUES(?,?,?)", (finding_id, kind, key))
            return self._finding_row(db, finding_id)

    def unlink_finding(self, finding_id: int, kind: str, key: str) -> dict:
        self._bump()
        kind, key = self._normalise_link({"kind": kind, "key": key})
        with self.lock, self.connect() as db:
            db.execute("DELETE FROM finding_links WHERE finding_id=? AND kind=? AND key=?", (finding_id, kind, key))
            return self._finding_row(db, finding_id)

    def findings_for(self, kind: str, key: str) -> list[dict]:
        """Findings that cite this relationship / asset / zone pair. A 'pair' query also matches
        findings linked only to relationships inside that pair."""
        kind, key = self._normalise_link({"kind": kind, "key": key})
        with self.connect() as db:
            ids = {r[0] for r in db.execute("SELECT finding_id FROM finding_links WHERE kind=? AND key=?", (kind, key))}
        if kind == "pair":
            rel_keys = {self.relationship_key(r["key_a"], r["key_b"]) for r in self.relationships(100000)
                        if self.pair_key(r["level_a"], r["level_b"]) == key}
            if rel_keys:
                with self.connect() as db:
                    for r in db.execute("SELECT finding_id,key FROM finding_links WHERE kind='relationship'"):
                        if r[1] in rel_keys:
                            ids.add(r[0])
        return [f for f in self.findings() if f["id"] in ids]

    @staticmethod
    def draft_key_for(draft: dict) -> str:
        key = draft.get("draft_key") or re.sub(r"[^a-z0-9]+", "-", draft["title"].lower()).strip("-")
        return key[:120]

    def import_draft_findings(self, drafts: list[dict]) -> int:
        """Add auto-drafted observations that are not already in the register.
        Matched by draft_key, so the assessor can retitle a finding without a re-import duplicating it;
        registers written before draft_key existed are matched by title once and back-filled."""
        added = 0
        with self.lock:
            with self.connect() as db:
                by_key = {row[0]: row[1] for row in db.execute("SELECT draft_key,id FROM findings WHERE draft_key<>''")}
                by_title = {row[0]: row[1] for row in db.execute("SELECT title,id FROM findings WHERE draft_key=''")}
                for draft in drafts:
                    dk = self.draft_key_for(draft)
                    fid = by_key.get(dk)
                    if fid is None and draft["title"] in by_title:
                        fid = by_title.pop(draft["title"])
                        db.execute("UPDATE findings SET draft_key=? WHERE id=?", (dk, fid))
                        by_key[dk] = fid
                    if fid is not None and draft.get("links"):
                        # keep the assessor's wording; only supply links where the finding has none yet
                        if not db.execute("SELECT 1 FROM finding_links WHERE finding_id=? LIMIT 1", (fid,)).fetchone():
                            self._replace_links(db, fid, draft["links"])
            for draft in drafts:
                dk = self.draft_key_for(draft)
                if dk in by_key:
                    continue
                kind = ("Positive observation" if draft["rating"] == "Positive" else
                        "Improvement opportunity" if draft["rating"] == "Informational" else "Evidence gap")
                horizon = "Immediate / quick win" if draft["rating"] == "High priority" else "Not applicable" if draft["rating"] == "Positive" else "30-90 days"
                row = self.save_finding({"title": draft["title"], "kind": kind, "rating": draft["rating"], "confidence": draft["confidence"],
                                         "owner": draft["owner"], "condition": draft["condition"], "evidence": draft["evidence"],
                                         "impact": draft["impact"], "recommendation": draft["recommendation"], "closure": draft["closure"],
                                         "horizon": horizon, "status": "Draft", "source": "OT Scout draft",
                                         "iec62443": draft.get("iec62443", ""), "attack": draft.get("attack", ""),
                                         "draft_key": dk, "links": draft.get("links", [])})
                by_key[dk] = row["id"]
                added += 1
        self._bump()
        return added

    def update_vendors(self) -> int:
        self._bump()
        count = self.vendors.update()
        with self.connect() as db:
            for row in db.execute("SELECT id,mac FROM assets"):
                db.execute("UPDATE assets SET vendor=? WHERE id=?", (self.vendors.lookup(row["mac"]), row["id"]))
        return count

    def reset(self):
        self._bump()
        with self.lock, self.connect() as db:
            db.executescript("DELETE FROM connections;DELETE FROM dns_names;DELETE FROM fingerprints;DELETE FROM asset_names;DELETE FROM asset_ips;DELETE FROM sightings;DELETE FROM assets;DELETE FROM sessions;DELETE FROM network_legs;DELETE FROM site_checklist;DELETE FROM sites;DELETE FROM finding_links;DELETE FROM findings;DELETE FROM conduits;DELETE FROM asset_aliases;")
