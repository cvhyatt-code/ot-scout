from __future__ import annotations

import io
import socket
import struct
import threading
import time
from pathlib import Path

from .parser import parse_ethernet


SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_DROP_MEMBERSHIP = 2
PACKET_MR_PROMISC = 1


class RateLimiter:
    """Caps processing to at most `rate` packets/sec by sleeping once the current
    one-second window's budget is spent. Purely a pacing knob for the assessor's
    own capture pipeline — it never touches the wire, since capture is read-only."""

    def __init__(self, rate: int | None):
        self.rate = rate or 0
        self._window_start = time.time()
        self._count = 0

    def tick(self):
        if not self.rate:
            return
        self._count += 1
        now = time.time()
        elapsed = now - self._window_start
        if elapsed >= 1.0:
            self._window_start = now
            self._count = 0
        elif self._count >= self.rate:
            time.sleep(max(0.0, self._window_start + 1.0 - now))
            self._window_start = time.time()
            self._count = 0


def interfaces() -> list[dict]:
    result = []
    try:
        discovered = socket.if_nameindex()
    except OSError:
        discovered = []
        for item in sorted(Path("/sys/class/net").glob("*")):
            try:
                discovered.append((socket.if_nametoindex(item.name), item.name))
            except OSError:
                discovered.append((0, item.name))
    for index, name in discovered:
        if name != "lo":
            result.append({"index": index, "name": name})
    return result


def interface_mac(name: str) -> str:
    try:
        return (Path("/sys/class/net") / name / "address").read_text().strip().lower()
    except OSError:
        return ""


def iter_pcap(data: bytes):
    stream = io.BytesIO(data)
    header = stream.read(24)
    if len(header) != 24:
        raise ValueError("PCAP header is missing")
    magic = header[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in formats:
        raise ValueError("Only classic Ethernet PCAP files are supported in this prototype")
    endian, divisor = formats[magic]
    _major, _minor, _zone, _sig, _snap, linktype = struct.unpack(endian + "HHIIII", header[4:])
    if linktype != 1:
        raise ValueError(f"Unsupported PCAP link type {linktype}; Ethernet is required")
    packet_header = struct.Struct(endian + "IIII")
    while True:
        raw = stream.read(16)
        if not raw:
            break
        if len(raw) != 16:
            raise ValueError("Truncated PCAP packet header")
        sec, fraction, captured, _original = packet_header.unpack(raw)
        frame = stream.read(captured)
        if len(frame) != captured:
            raise ValueError("Truncated PCAP frame")
        yield sec + fraction / divisor, frame


class CaptureManager:
    def __init__(self, store):
        self.store = store
        self.thread = None
        self.stop_event = threading.Event()
        self.sock = None
        self.session_id = None
        self.interface = ""
        self.error = ""
        self.started_at = None
        self.stopped_at = None
        self.rate_limit = None

    @property
    def running(self):
        return bool(self.thread and self.thread.is_alive())

    def start(self, assessment: str, site: str, point: str, interface: str, access_method: str, rate_limit: int | None = None):
        if self.running:
            raise RuntimeError("A capture is already running")
        available = {item["name"] for item in interfaces()}
        if interface not in available:
            raise ValueError("Selected interface does not exist")
        self.error = ""
        self.interface = interface
        self.local_mac = interface_mac(interface)
        self.rate_limit = rate_limit or None
        self.stop_event.clear()
        self.session_id = self.store.begin_session(assessment, site, point, interface, "live", access_method)
        self.started_at = time.time()
        self.stopped_at = None
        self.thread = threading.Thread(target=self._run, daemon=True, name="passive-capture")
        self.thread.start()
        return self.session_id

    def _run(self):
        membership = None
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            self.sock = sock
            sock.bind((self.interface, 0))
            ifindex = socket.if_nametoindex(self.interface)
            membership = struct.pack("IHH8s", ifindex, PACKET_MR_PROMISC, 0, b"")
            try:
                sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, membership)
            except OSError:
                membership = None
            sock.settimeout(1.0)
            limiter = RateLimiter(self.rate_limit)
            while not self.stop_event.is_set():
                try:
                    frame = sock.recv(65535)
                except socket.timeout:
                    continue
                obs = parse_ethernet(frame, time.time())
                if obs:
                    self.store.record(self.session_id, obs, self.local_mac)
                limiter.tick()
        except PermissionError:
            self.error = "Packet capture permission denied. Start with sudo."
        except OSError as exc:
            if not self.stop_event.is_set():
                self.error = f"Capture failed: {exc}"
        finally:
            if self.sock:
                if membership:
                    try: self.sock.setsockopt(SOL_PACKET, PACKET_DROP_MEMBERSHIP, membership)
                    except OSError: pass
                try: self.sock.close()
                except OSError: pass
            self.sock = None
            self.stopped_at = time.time()
            if self.session_id:
                self.store.end_session(self.session_id)

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3)

    def elapsed_seconds(self) -> int | None:
        """Seconds the current capture has run, or the final duration of the last one."""
        if self.started_at is None:
            return None
        end = time.time() if self.running or self.stopped_at is None else self.stopped_at
        return max(0, int(end - self.started_at))

    def status(self):
        return {"running": self.running, "interface": self.interface, "session_id": self.session_id,
                "error": self.error, "started_at": self.started_at, "stopped_at": self.stopped_at,
                "elapsed_seconds": self.elapsed_seconds(), "rate_limit": self.rate_limit}

    def import_pcap(self, data: bytes, assessment: str, site: str, point: str, filename: str, rate_limit: int | None = None) -> dict:
        session_id = self.store.begin_session(assessment, site, point, filename, "pcap", "Imported PCAP")
        count = 0
        limiter = RateLimiter(rate_limit)
        try:
            for timestamp, frame in iter_pcap(data):
                obs = parse_ethernet(frame, timestamp)
                if obs:
                    self.store.record(session_id, obs)
                    count += 1
                limiter.tick()
        finally:
            self.store.end_session(session_id)
        return {"session_id": session_id, "packets": count}
