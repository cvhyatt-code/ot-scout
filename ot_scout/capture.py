from __future__ import annotations

import io
import queue
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
SO_RCVBUFFORCE = 33       # root may exceed net.core.rmem_max with this; plain SO_RCVBUF is silently capped

BATCH_SIZE = 200          # frames per database transaction
BATCH_INTERVAL = 0.25     # seconds — flush at least this often so the UI stays live on a quiet network
RCVBUF_BYTES = 64 * 1024 * 1024   # socket receive buffer to ask for; the kernel default (~200 KB) fills in milliseconds on a busy SPAN
QUEUE_FRAMES = 300_000    # frames the reader may hand the parser before it must wait for it; ~30-60 s of a busy mirror in memory
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"   # Wireshark and dumpcap write this by default; OT Scout reads classic pcap


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


def capture_supported() -> bool:
    """Live capture needs Linux AF_PACKET. Everything downstream of capture is portable."""
    return hasattr(socket, "AF_PACKET")


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
    if magic == PCAPNG_MAGIC:
        raise ValueError("This is a pcapng file — Wireshark and dumpcap write pcapng by default, and OT Scout "
                         "reads classic libpcap. Convert it with:  editcap -F libpcap in.pcapng out.pcap  "
                         "(or capture in pcap format to begin with:  dumpcap -P -w out.pcap)")
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
        self.parsed = 0           # frames the parser thread has processed
        self.unparsed = 0         # frames written to the PCAP but skipped by the live parser (queue full)
        self.rcvbuf = 0           # receive buffer the kernel actually granted, bytes
        self.queue = None

    @property
    def running(self):
        return bool(self.thread and self.thread.is_alive())

    @property
    def finishing(self) -> bool:
        """Reader has stopped but the parser is still draining what it was handed."""
        return bool(self.thread and self.thread.is_alive() and self.stop_event.is_set())

    def start(self, assessment: str, site: str, point: str, interface: str, access_method: str, rate_limit: int | None = None,
              save_pcap: bool = True):
        if not capture_supported():
            raise RuntimeError("Live capture requires Linux — it uses AF_PACKET, which this platform does not "
                               "provide. Import a PCAP instead: everything after capture (inventory, zones, "
                               "conduits, findings, the report) runs on any platform.")
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
        self.frames = self.dropped = self.kernel_seen = self.parsed = self.unparsed = 0
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
        """Reader thread. Does as little as possible per frame — recv, PCAP write, hand to the parser — because
        every microsecond spent here is receive-buffer time, and the buffer filling is what the kernel counts as
        a drop. Parsing and SQLite happen in _parse_loop on another thread; the throttle paces that thread, never
        this one."""
        membership = None
        writer = None
        parser = None
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            self.sock = sock
            self.rcvbuf = self._grow_rcvbuf(sock)
            sock.bind((self.interface, 0))
            ifindex = socket.if_nametoindex(self.interface)
            membership = struct.pack("IHH8s", ifindex, PACKET_MR_PROMISC, 0, b"")
            try:
                sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, membership)
            except OSError:
                membership = None
            sock.settimeout(0.2)
            writer = PcapWriter(Path(self.pcap_path)) if self.pcap_path else None
            self.queue = queue.Queue(QUEUE_FRAMES)
            parser = threading.Thread(target=self._parse_loop, daemon=True, name="passive-parse")
            parser.start()
            last_stats = time.time()
            recv, put, qfull = sock.recv, self.queue.put, self.queue.full
            while not self.stop_event.is_set():
                try:
                    frame = recv(65535)
                except socket.timeout:
                    self._read_stats(sock)
                    continue
                now = time.time()
                self.frames += 1
                if writer:
                    writer.write(frame, now)
                if qfull():
                    # the parser is behind by QUEUE_FRAMES; the frame is on disk in the PCAP but will not be
                    # parsed live — counted separately from kernel drops because it is recoverable by re-import
                    self.unparsed += 1
                else:
                    put((frame, now))
                if now - last_stats >= 1.0:
                    self._read_stats(sock); last_stats = now
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
            if parser is not None:
                self.queue.put(None)          # sentinel: parse what is queued, then finish the session
                parser.join()
            elif self.session_id:
                self.store.end_session(self.session_id, dropped=self.dropped, frames=self.frames)

    def _parse_loop(self):
        """Parser thread: drain the queue into batched SQLite writes. Keeps going after the reader stops until
        everything the reader handed over is in the database, then closes the session."""
        limiter = RateLimiter(self.rate_limit)
        batch = []
        last_flush = time.time()
        try:
            while True:
                try:
                    item = self.queue.get(timeout=BATCH_INTERVAL)
                except queue.Empty:
                    item = False
                if item is None:
                    break
                if item is not False:
                    frame, ts = item
                    obs = parse_ethernet(frame, ts)
                    if obs:
                        batch.append(obs)
                    self.parsed += 1
                    limiter.tick()
                now = time.time()
                if batch and (len(batch) >= BATCH_SIZE or now - last_flush >= BATCH_INTERVAL):
                    self.store.record_many(self.session_id, batch, self.local_mac)
                    batch = []
                    last_flush = now
            if batch:
                self.store.record_many(self.session_id, batch, self.local_mac)
        finally:
            if self.session_id:
                self.store.end_session(self.session_id, dropped=self.dropped, frames=self.frames)

    @staticmethod
    def _grow_rcvbuf(sock) -> int:
        """Ask for a large receive buffer. SO_RCVBUFFORCE (root) ignores net.core.rmem_max; fall back to
        SO_RCVBUF, which the kernel caps at rmem_max (~200 KB by default). Returns what we actually got."""
        for opt in (SO_RCVBUFFORCE, socket.SO_RCVBUF):
            try:
                sock.setsockopt(socket.SOL_SOCKET, opt, RCVBUF_BYTES)
                break
            except OSError:
                continue
        try:
            return sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        except OSError:
            return 0

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
        """Stop reading. The session is closed by the parser thread once the queue is drained; status()
        reports finishing=True and the remaining queued count until then."""
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
                "frames": self.frames, "dropped": self.dropped, "pcap_path": self.pcap_path, "save_pcap": self.save_pcap,
                "parsed": self.parsed, "unparsed": self.unparsed, "queued": self.queue.qsize() if self.queue else 0,
                "finishing": self.finishing, "rcvbuf": self.rcvbuf}

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
