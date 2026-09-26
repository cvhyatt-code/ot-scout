"""What the tool does when the input was chosen by someone who wants it to break.

Three boundaries, none of which require any access to the assessor's laptop: the frames on the
monitored network, the parser thread that decodes them, and the assessor's own browser being talked
into acting against the loopback interface by some other page.
"""
import http.client
import queue
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ot_scout import capture as capture_mod
from ot_scout.bind import allowed_hosts, bare_host, host_header_ok, origin_ok
from ot_scout.capture import CaptureManager
from ot_scout.cip import MAX_ROUTE_DEPTH, _request_target

TOKEN = "hostile-input-test-token"

GET_ATTRIBUTE_SINGLE = bytes([0x0E, 0x02, 0x20, 0x01, 0x24, 0x01])


def unconnected_send(inner: bytes) -> bytes:
    """Wrap a CIP request in an Unconnected_Send addressed to the connection manager."""
    return bytes([0x52, 0x02, 0x20, 0x06, 0x24, 0x01, 0x05, 0x99]) + struct.pack("<H", len(inner)) + inner


class RecordingStore:
    path = "/tmp/ot-scout-hostile-test.db"

    def __init__(self):
        self.batches = []
        self.ended = []

    def record_many(self, session_id, batch, local_mac):
        self.batches.append(list(batch))

    def end_session(self, session_id, dropped=0, frames=0):
        self.ended.append(session_id)


class DeadParser:
    @staticmethod
    def is_alive():
        return False


class DrainingParser:
    """Alive, and makes room on the queue the way a real parser thread eventually would."""

    def __init__(self, q):
        self.q = q
        self.calls = 0

    def is_alive(self):
        self.calls += 1
        if self.calls == 2:
            self.q.get()
        return True


class CipRoutingDepthTests(unittest.TestCase):
    """A crafted frame must not be able to recurse the decoder off the end of the stack."""

    def test_one_hop_unwraps_to_the_embedded_request(self):
        service, path = _request_target(unconnected_send(GET_ATTRIBUTE_SINGLE))
        self.assertEqual(service, 0x0E)
        self.assertEqual(path["class"], 0x01)

    def test_routing_within_the_limit_still_unwraps(self):
        frame = GET_ATTRIBUTE_SINGLE
        for _ in range(MAX_ROUTE_DEPTH):
            frame = unconnected_send(frame)
        self.assertEqual(_request_target(frame)[0], 0x0E)

    def test_deep_nesting_is_refused_instead_of_exhausting_the_stack(self):
        frame = GET_ATTRIBUTE_SINGLE
        for _ in range(2000):
            frame = unconnected_send(frame)
        self.assertIsNone(_request_target(frame))


class ParserThreadSurvivalTests(unittest.TestCase):
    """A frame the decoder cannot survive costs that frame, not the capture."""

    def test_an_undecodable_frame_does_not_stop_the_parser(self):
        store = RecordingStore()
        manager = CaptureManager(store)
        manager.session_id = 1
        manager.queue = queue.Queue(10)
        seen = []

        def flaky(frame, ts):
            if frame == b"hostile":
                raise struct.error("unpack requires a buffer of 4 bytes")
            seen.append(frame)
            return None

        original = capture_mod.parse_ethernet
        capture_mod.parse_ethernet = flaky
        try:
            manager.queue.put((b"hostile", 1.0))
            manager.queue.put((b"ordinary", 2.0))
            manager.queue.put(None)
            manager._parse_loop()
        finally:
            capture_mod.parse_ethernet = original

        self.assertEqual(manager.malformed, 1)
        self.assertEqual(manager.parsed, 2)
        self.assertEqual(seen, [b"ordinary"])
        self.assertEqual(store.ended, [1], "the session must still be closed")

    def test_a_recursion_error_is_contained_like_any_other(self):
        manager = CaptureManager(RecordingStore())
        manager.session_id = 1
        manager.queue = queue.Queue(10)
        original = capture_mod.parse_ethernet

        def explode(frame, ts):
            raise RecursionError("maximum recursion depth exceeded")

        capture_mod.parse_ethernet = explode
        try:
            manager.queue.put((b"deep", 1.0))
            manager.queue.put(None)
            manager._parse_loop()
        finally:
            capture_mod.parse_ethernet = original
        self.assertEqual(manager.malformed, 1)


class StopSentinelTests(unittest.TestCase):
    """Stopping a busy capture must not depend on the parser thread still being there."""

    def test_reader_gives_up_when_the_parser_is_gone(self):
        manager = CaptureManager(RecordingStore())
        manager.queue = queue.Queue(1)
        manager.queue.put((b"frame", 1.0))
        started = time.monotonic()
        self.assertFalse(manager._hand_over_sentinel(DeadParser()))
        self.assertLess(time.monotonic() - started, 1.0, "a dead parser must not hold the reader")

    def test_reader_waits_for_a_parser_that_is_still_draining(self):
        manager = CaptureManager(RecordingStore())
        manager.queue = queue.Queue(1)
        manager.queue.put((b"frame", 1.0))
        self.assertTrue(manager._hand_over_sentinel(DrainingParser(manager.queue)))


class HostHeaderTests(unittest.TestCase):
    """DNS rebinding: the attacker's hostname resolves to 127.0.0.1, so only the Host header shows it."""

    def setUp(self):
        self.allowed = allowed_hosts("127.0.0.1")

    def test_expected_names_are_answered(self):
        for value in ("127.0.0.1:8080", "127.0.0.1", "localhost:8080", "LOCALHOST", "[::1]:8080"):
            self.assertTrue(host_header_ok(value, self.allowed), value)

    def test_a_foreign_name_is_refused(self):
        for value in ("ot-scout.attacker.test", "evil.example:8080", "", None):
            self.assertFalse(host_header_ok(value, self.allowed), value)

    def test_a_wildcard_bind_still_checks_the_name(self):
        self.assertTrue(host_header_ok("localhost:8767", allowed_hosts("0.0.0.0")))
        self.assertFalse(host_header_ok("collector.lan.example", allowed_hosts("0.0.0.0")))
        self.assertTrue(host_header_ok("collector.lan.example", allowed_hosts("0.0.0.0", ["collector.lan.example"])))

    def test_a_specific_bind_address_answers_to_itself(self):
        self.assertTrue(host_header_ok("192.0.2.10:8767", allowed_hosts("192.0.2.10")))
        self.assertFalse(host_header_ok("192.0.2.11:8767", allowed_hosts("192.0.2.10")))


class OriginTests(unittest.TestCase):
    def setUp(self):
        self.allowed = allowed_hosts("127.0.0.1")

    def test_absent_origin_is_a_non_browser_client(self):
        self.assertTrue(origin_ok(None, self.allowed))

    def test_our_own_page_is_allowed(self):
        for value in ("http://127.0.0.1:8080", "http://localhost:8080"):
            self.assertTrue(origin_ok(value, self.allowed), value)

    def test_a_foreign_page_is_refused(self):
        for value in ("http://evil.example", "https://evil.example:8080", "null"):
            self.assertFalse(origin_ok(value, self.allowed), value)


class GuardWiringTests(unittest.TestCase):
    """The checks above, reached through the real handler rather than called directly."""

    @classmethod
    def setUpClass(cls):
        from ot_scout.store import Store
        from ot_scout.web import AppServer, Handler
        cls.tmp = tempfile.TemporaryDirectory()
        store = Store(str(Path(cls.tmp.name) / "guard.db"))
        cls.server = AppServer(("127.0.0.1", 0), Handler, store, CaptureManager(store), token=TOKEN)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def request(self, method, path, host=None, origin=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", f"127.0.0.1:{self.port}" if host is None else host)
            if origin:
                conn.putheader("Origin", origin)
            conn.putheader("X-Scout-Token", TOKEN)
            payload = b"{}"
            if method == "POST":
                conn.putheader("Content-Type", "application/json")
                conn.putheader("Content-Length", str(len(payload)))
            conn.endheaders()
            if method == "POST":
                conn.send(payload)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_an_ordinary_request_is_answered(self):
        status, _ = self.request("GET", "/api/status")
        self.assertEqual(status, 200)

    def test_a_rebinding_host_is_refused(self):
        status, body = self.request("GET", "/api/status", host="ot-scout.attacker.test")
        self.assertEqual(status, 421)
        self.assertIn(b"Host", body)

    def test_a_cross_origin_post_is_refused(self):
        status, body = self.request("POST", "/api/stop", origin="http://evil.example")
        self.assertEqual(status, 403)
        self.assertIn(b"Cross-origin", body)

    def test_a_same_origin_post_still_works(self):
        status, _ = self.request("POST", "/api/stop", origin=f"http://127.0.0.1:{self.port}")
        self.assertEqual(status, 200)



class TunnelHostTests(unittest.TestCase):
    """A tunnel the assessor set up must get through without switching the rebinding check off.

    A reverse proxy that preserves the name the browser typed makes a loopback bind see a
    Host header no process on this machine could have guessed. Naming it is the fix. Naming it must
    not turn into accepting everything, which is the failure mode worth testing for.
    """

    PROXY_NAME = "collector.proxy.example"

    def setUp(self):
        self.allowed = allowed_hosts("127.0.0.1", [self.PROXY_NAME])

    def test_the_named_tunnel_host_is_answered(self):
        for value in (self.PROXY_NAME, f"{self.PROXY_NAME}:8443", self.PROXY_NAME.upper(), f"{self.PROXY_NAME}."):
            self.assertTrue(host_header_ok(value, self.allowed), value)

    def test_loopback_still_works_alongside_it(self):
        for value in ("127.0.0.1:8080", "localhost", "[::1]:8080"):
            self.assertTrue(host_header_ok(value, self.allowed), value)

    def test_every_other_name_is_still_refused(self):
        for value in ("evil.example", "collector.proxy.example.evil.example",
                      "other-collector.proxy.example", "attacker.test:8443"):
            self.assertFalse(host_header_ok(value, self.allowed), value)

    def test_a_page_served_from_the_tunnel_may_post(self):
        self.assertTrue(origin_ok(f"https://{self.PROXY_NAME}:8443", self.allowed))

    def test_a_page_served_from_anywhere_else_may_not(self):
        for value in ("https://evil.example", f"https://evil.example/{self.PROXY_NAME}", "null"):
            self.assertFalse(origin_ok(value, self.allowed), value)

    def test_the_flag_accepts_a_name_with_a_port(self):
        # The command line invites "the URL I type", which carries a port. If the allowlist stored it
        # verbatim it would never match, because the incoming Host has its port stripped before the
        # comparison — an allowlist entry that silently never matches is the worst kind.
        with_port = allowed_hosts("127.0.0.1", [f"{self.PROXY_NAME}:8443"])
        self.assertTrue(host_header_ok(f"{self.PROXY_NAME}:8443", with_port))
        self.assertTrue(host_header_ok(self.PROXY_NAME, with_port))

    def test_blank_entries_do_not_widen_anything(self):
        self.assertEqual(allowed_hosts("127.0.0.1", ["", "   ", None]), allowed_hosts("127.0.0.1"))

    def test_extra_names_apply_on_a_wildcard_bind_too(self):
        self.assertTrue(host_header_ok(self.PROXY_NAME, allowed_hosts("0.0.0.0", [self.PROXY_NAME])))

    def test_bare_host_is_what_both_sides_agree_on(self):
        self.assertEqual(bare_host("  Collector.PROXY.example:8443 "), "collector.proxy.example")
        self.assertEqual(bare_host("[::1]:8080"), "[::1]")
        self.assertEqual(bare_host("::1"), "::1")


class TunnelWiringTests(unittest.TestCase):
    """The tunnel name, reached through the real handler."""

    PROXY_NAME = "collector.proxy.example"

    @classmethod
    def setUpClass(cls):
        from ot_scout.store import Store
        from ot_scout.web import AppServer, Handler
        cls.tmp = tempfile.TemporaryDirectory()
        store = Store(str(Path(cls.tmp.name) / "tunnel.db"))
        cls.server = AppServer(("127.0.0.1", 0), Handler, store, CaptureManager(store), allowed=[cls.PROXY_NAME], token=TOKEN)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def request(self, method, path, host, origin=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", host)
            if origin:
                conn.putheader("Origin", origin)
            conn.putheader("X-Scout-Token", TOKEN)
            payload = b"{}"
            if method == "POST":
                conn.putheader("Content-Type", "application/json")
                conn.putheader("Content-Length", str(len(payload)))
            conn.endheaders()
            if method == "POST":
                conn.send(payload)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_a_get_through_the_tunnel_is_answered(self):
        status, _ = self.request("GET", "/api/status", f"{self.PROXY_NAME}:8443")
        self.assertEqual(status, 200)

    def test_a_post_from_the_tunnel_page_is_answered(self):
        status, _ = self.request("POST", "/api/stop", f"{self.PROXY_NAME}:8443", f"https://{self.PROXY_NAME}:8443")
        self.assertEqual(status, 200)

    def test_another_name_pointed_at_this_port_is_still_refused(self):
        status, body = self.request("GET", "/api/status", "ot-scout.attacker.test")
        self.assertEqual(status, 421)
        self.assertIn(b"attacker.test", body, "the refusal should name what it refused")
        self.assertIn(b"--allowed-host", body, "and say what to do if the tunnel is yours")


class TokenTests(unittest.TestCase):
    """The per-launch token: every state-changing request must carry it, in a header."""

    @classmethod
    def setUpClass(cls):
        from ot_scout.store import Store
        from ot_scout.web import AppServer, Handler
        cls.tmp = tempfile.TemporaryDirectory()
        store = Store(str(Path(cls.tmp.name) / "token.db"))
        cls.server = AppServer(("127.0.0.1", 0), Handler, store, CaptureManager(store), token=TOKEN)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def request(self, method, path, token=None, host=None, origin=None, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", host or f"127.0.0.1:{self.port}")
            if origin:
                conn.putheader("Origin", origin)
            if token is not None:
                conn.putheader("X-Scout-Token", token)
            if cookie:
                conn.putheader("Cookie", cookie)
            payload = b"{}"
            if method == "POST":
                conn.putheader("Content-Type", "application/json")
                conn.putheader("Content-Length", str(len(payload)))
            conn.endheaders()
            if method == "POST":
                conn.send(payload)
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_a_post_with_the_token_is_answered(self):
        self.assertEqual(self.request("POST", "/api/stop", token=TOKEN)[0], 200)

    def test_a_post_with_no_token_is_refused(self):
        status, _, body = self.request("POST", "/api/stop")
        self.assertEqual(status, 401)
        self.assertIn(b"token", body)

    def test_a_post_with_a_wrong_token_is_refused(self):
        for wrong in ("", "nope", TOKEN + "x", TOKEN.upper()):
            self.assertEqual(self.request("POST", "/api/stop", token=wrong)[0], 401, wrong)

    def test_the_cookie_alone_does_not_authorise_a_post(self):
        cookie = f"{self.server.cookie}={TOKEN}"
        self.assertEqual(self.request("POST", "/api/stop", cookie=cookie)[0], 401)

    def test_a_foreign_origin_is_refused_even_with_the_token(self):
        self.assertEqual(self.request("POST", "/api/stop", token=TOKEN, origin="http://evil.example")[0], 403)

    def test_a_foreign_host_is_refused_even_with_the_token(self):
        self.assertEqual(self.request("POST", "/api/stop", token=TOKEN, host="evil.example")[0], 421)

    def test_reads_need_the_token_too(self):
        self.assertEqual(self.request("GET", "/api/status")[0], 401)
        self.assertEqual(self.request("GET", "/api/status", token=TOKEN)[0], 200)
        self.assertEqual(self.request("GET", "/api/status", cookie=f"{self.server.cookie}={TOKEN}")[0], 200)

    def test_the_first_response_to_the_startup_url_is_the_page_with_a_lax_cookie(self):
        """Opened from another app (a terminal), the browser treats the startup URL as a cross-site
        navigation. So the page comes back on that first response, with no redirect that would need the
        cookie sent straight back, and the cookie is Lax so later navigations carry it."""
        status, headers, page = self.request("GET", f"/?token={TOKEN}")
        self.assertEqual(status, 200)
        self.assertNotIn("Location", headers)
        self.assertIn('data-tab="collect"', page.decode("utf-8"), "the app page itself, not a stub")
        cookie = headers["Set-Cookie"]
        self.assertTrue(cookie.startswith(f"{self.server.cookie}={TOKEN};"))
        attributes = [a.strip() for a in cookie.split(";")[1:]]
        self.assertIn("SameSite=Lax", attributes)
        self.assertIn("HttpOnly", attributes)
        self.assertIn("Path=/", attributes)
        self.assertIn(b"history.replaceState", page, "the page takes the token out of the address bar")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        status, _, page = self.request("GET", "/", cookie=cookie.split(";")[0])
        self.assertEqual(status, 200)
        self.assertIn(TOKEN.encode(), page)

    def test_the_page_without_the_token_explains_what_to_do(self):
        status, _, page = self.request("GET", "/")
        self.assertEqual(status, 401)
        self.assertIn(b"printed", page)
        self.assertNotIn(TOKEN.encode(), page)
        self.assertEqual(self.request("GET", "/?token=wrong")[0], 401)

    def test_each_server_gets_a_fresh_token(self):
        from ot_scout.store import Store
        from ot_scout.web import AppServer, Handler
        store = Store(str(Path(self.tmp.name) / "fresh.db"))
        a = AppServer(("127.0.0.1", 0), Handler, store, CaptureManager(store))
        b = AppServer(("127.0.0.1", 0), Handler, store, CaptureManager(store))
        try:
            self.assertNotEqual(a.token, b.token)
            self.assertGreaterEqual(len(a.token), 32)
        finally:
            a.server_close(); b.server_close()


if __name__ == "__main__":
    unittest.main()
