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
PACKET_STATISTICS = 6
PACKET_MR_PROMISC = 1

BATCH_SIZE = 200          # frames per database transaction
BATCH_INTERVAL = 0.25     # seconds — flush at least this often so the UI stays live on a quiet network
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"


class PcapWriter:
    """Classic pcap (libpcap 2.4, Ethernet, microsecond timestamps) — the raw evidence of record."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.fh = open(path, "wb")
        self.fh.write(PCAP_MAGIC_LE + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1))
        self.frames = 0
        self._since_flush = 0

    def write(self, frame: bytes, timestamp: float):
        sec = int(timestamp)
        usec = int((timestamp - sec) * 1_000_000)
        self.fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self.fh.write(frame)
        self.frames += 1
        self._since_flush += 1
        if self._since_flush >= 500:
            self.fh.flush(); self._since_flush = 0

    def close(self):
        try:
            self.fh.flush(); self.fh.close()
        except OSError:
            pass


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
    def __init__(self, store, captures_dir: Path | None = None):
        self.store = store
        self.captures_dir = Path(captures_dir) if captures_dir else Path(store.path).resolve().parent / "captures"
        self.thread = None
        self.stop_event = threading.Event()
        self.sock = None
        self.session_id = None
        self.interface = ""
        self.error = ""
        self.started_at = None
        self.stopped_at = None
        self.rate_limit = None
        self.save_pcap = True
        self.pcap_path = ""
        self.frames = 0           # frames this capture has read from the socket
        self.dropped = 0          # frames the kernel dropped because we read too slowly (PACKET_STATISTICS)
        self.kernel_seen = 0      # frames the kernel counted for the socket (read + dropped)

    @property
    def running(self):
        return bool(self.thread and self.thread.is_alive())

    def start(self, assessment: str, site: str, point: str, interface: str, access_method: str, rate_limit: int | None = None,
              save_pcap: bool = True):
        if self.running:
            raise RuntimeError("A capture is already running")
        available = {item["name"] for item in interfaces()}
        if interface not in available:
            raise ValueError("Selected interface does not exist")
        self.error = ""
        self.interface = interface
        self.local_mac = interface_mac(interface)
        self.rate_limit = rate_limit or None
        self.save_pcap = bool(save_pcap)
        self.pcap_path = ""
        self.frames = self.dropped = self.kernel_seen = 0
        self.stop_event.clear()
        self.session_id = self.store.begin_session(assessment, site, point, interface, "live", access_method)
        if self.save_pcap:
            stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
            safe_point = "".join(c if c.isalnum() or c in "-_" else "_" for c in point)[:40] or "capture"
            self.pcap_path = str(self.captures_dir / f"session-{self.session_id:03d}-{safe_point}-{stamp}.pcap")
            self.store.set_session_pcap(self.session_id, self.pcap_path)
        self.started_at = time.time()
        self.stopped_at = None
        self.thread = threading.Thread(target=self._run, daemon=True, name="passive-capture")
        self.thread.start()
        return self.session_id

    def _run(self):
        membership = None
        writer = None
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
            sock.settimeout(0.2)
            limiter = RateLimiter(self.rate_limit)
            writer = PcapWriter(Path(self.pcap_path)) if self.pcap_path else None
            batch = []
            last_flush = last_stats = time.time()

            def flush():
                nonlocal batch, last_flush
                if batch:
                    self.store.record_many(self.session_id, batch, self.local_mac)
                    batch = []
                last_flush = time.time()

            while not self.stop_event.is_set():
                try:
                    frame = sock.recv(65535)
                except socket.timeout:
                    if batch and time.time() - last_flush >= BATCH_INTERVAL:
                        flush()
                    self._read_stats(sock)
                    continue
                now = time.time()
                self.frames += 1
                if writer:
                    writer.write(frame, now)
                obs = parse_ethernet(frame, now)
                if obs:
                    batch.append(obs)
                if len(batch) >= BATCH_SIZE or now - last_flush >= BATCH_INTERVAL:
                    flush()
                if now - last_stats >= 1.0:
                    self._read_stats(sock); last_stats = now
                limiter.tick()
            flush()
            self._read_stats(sock)
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
            if writer:
                writer.close()
            if self.session_id:
                self.store.end_session(self.session_id, dropped=self.dropped, frames=self.frames)

    def _read_stats(self, sock):
        """PACKET_STATISTICS returns (packets, drops) since the last read and resets — accumulate."""
        try:
            raw = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            packets, drops = struct.unpack("II", raw[:8])
        except (OSError, struct.error):
            return
        self.kernel_seen += packets
        self.dropped += drops

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
                "elapsed_seconds": self.elapsed_seconds(), "rate_limit": self.rate_limit,
                "frames": self.frames, "dropped": self.dropped, "pcap_path": self.pcap_path, "save_pcap": self.save_pcap}

    def import_pcap(self, data: bytes, assessment: str, site: str, point: str, filename: str, rate_limit: int | None = None) -> dict:
        session_id = self.store.begin_session(assessment, site, point, filename, "pcap", "Imported PCAP")
        count = frames = 0
        limiter = RateLimiter(rate_limit)
        batch = []
        try:
            for timestamp, frame in iter_pcap(data):
                frames += 1
                obs = parse_ethernet(frame, timestamp)
                if obs:
                    batch.append(obs)
                    count += 1
                if len(batch) >= BATCH_SIZE:
                    self.store.record_many(session_id, batch); batch = []
                limiter.tick()
            self.store.record_many(session_id, batch)
        finally:
            self.store.end_session(session_id, frames=frames)
        return {"session_id": session_id, "packets": count}
