"""The capture pipeline and the web guard around PCAP import."""
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path


class CapturePipelineTests(unittest.TestCase):
    """The reader/parser split without a raw socket: feed the parser thread directly."""

    def test_parser_thread_drains_queue_and_closes_session(self):
        import queue as _q
        from ot_scout.capture import CaptureManager, iter_pcap
        from ot_scout.store import Store
        data = (Path(__file__).parent / "fixtures" / "opcua-asyncua.pcap").read_bytes()
        frames = list(iter_pcap(data))
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(str(Path(tmp) / "t.db"))
            cap = CaptureManager(store)
            cap.session_id = store.begin_session("A", "S", "P", "eth0", "live", "SPAN")
            cap.local_mac = ""
            cap.queue = _q.Queue()
            for ts, frame in frames:
                cap.queue.put((frame, ts))
            cap.queue.put(None)
            cap._parse_loop()
            self.assertEqual(cap.parsed, len(frames))
            self.assertGreater(store.dashboard()["flows"], 0)
            sess = store.sessions()[0]
            self.assertIsNotNone(sess["ended_at"])

    def test_status_carries_pipeline_fields(self):
        from ot_scout.capture import CaptureManager
        from ot_scout.store import Store
        with tempfile.TemporaryDirectory() as tmp:
            cap = CaptureManager(Store(str(Path(tmp) / "t.db")))
            st = cap.status()
            for key in ("parsed", "unparsed", "queued", "finishing", "rcvbuf"):
                self.assertIn(key, st)
            self.assertFalse(st["finishing"])

    def test_rcvbuf_request_is_large(self):
        import socket
        from ot_scout.capture import CaptureManager
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            got = CaptureManager._grow_rcvbuf(s)
        finally:
            s.close()
        # unprivileged: capped at rmem_max, but still at least the kernel default; root: the full request
        self.assertGreaterEqual(got, 128 * 1024)


class ImportGuardTests(unittest.TestCase):
    def test_import_refused_while_capturing(self):
        from ot_scout.capture import CaptureManager
        from ot_scout.store import Store
        from ot_scout.web import AppServer, Handler
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(str(Path(tmp) / "t.db"))
            cap = CaptureManager(store)
            server = AppServer(("127.0.0.1", 0), Handler, store, cap, token="t")
            port = server.server_address[1]
            t = threading.Thread(target=server.serve_forever, daemon=True); t.start()
            try:
                class Fake:
                    def is_alive(self): return True
                cap.thread = Fake()  # looks like a running capture
                req = urllib.request.Request(f"http://127.0.0.1:{port}/api/import-pcap", data=b"", method="POST",
                                             headers={"X-Scout-Token": "t", "X-Assessment": "A", "X-Site": "S", "X-Collection-Point": "P", "X-Filename": "f.pcap"})
                try:
                    urllib.request.urlopen(req, timeout=5); self.fail("expected 400")
                except urllib.error.HTTPError as e:
                    self.assertEqual(e.code, 400)
                    self.assertIn("Stop the live capture", json.loads(e.read())["error"])
            finally:
                server.shutdown(); server.server_close()


if __name__ == "__main__":
    unittest.main()
