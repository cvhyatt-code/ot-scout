import socket
import struct
import unittest

from ot_scout.bind import bind_refusal, exposure_banner, is_loopback
from ot_scout import capture as capture_mod
from ot_scout.capture import CaptureManager, iter_pcap


class StubStore:
    path = "/tmp/ot-scout-test.db"


class LoopbackTests(unittest.TestCase):
    def test_loopback_addresses(self):
        for host in ("127.0.0.1", "127.0.0.53", "localhost", "LOCALHOST", " 127.0.0.1 ", "::1"):
            self.assertTrue(is_loopback(host), host)

    def test_non_loopback_addresses(self):
        for host in ("0.0.0.0", "192.168.1.10", "10.0.0.5", "", "::"):
            self.assertFalse(is_loopback(host), host)


class BindRefusalTests(unittest.TestCase):
    def test_loopback_is_allowed(self):
        self.assertIsNone(bind_refusal("127.0.0.1", False))

    def test_non_loopback_is_refused_and_explains_itself(self):
        message = bind_refusal("0.0.0.0", False)
        self.assertIsNotNone(message)
        self.assertIn("no authentication", message)
        self.assertIn("--insecure-bind", message)
        self.assertIn("ssh -L", message)

    def test_explicit_flag_permits_it(self):
        self.assertIsNone(bind_refusal("0.0.0.0", True))

    def test_banner_names_what_is_exposed(self):
        banner = exposure_banner("0.0.0.0", 8080)
        self.assertIn("0.0.0.0:8080", banner)
        self.assertIn("NO AUTHENTICATION", banner)
        self.assertIn("evidence package", banner)


class PcapngTests(unittest.TestCase):
    def test_pcapng_names_the_conversion_command(self):
        pcapng = b"\x0a\x0d\x0d\x0a" + b"\x00" * 20
        with self.assertRaises(ValueError) as ctx:
            list(iter_pcap(pcapng))
        self.assertIn("pcapng", str(ctx.exception))
        self.assertIn("editcap -F libpcap", str(ctx.exception))

    def test_classic_pcap_still_parses(self):
        header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        frame = b"\xff" * 14
        body = struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
        self.assertEqual(len(list(iter_pcap(header + body))), 1)

    def test_unknown_magic_still_rejected(self):
        with self.assertRaises(ValueError):
            list(iter_pcap(b"nope" + b"\x00" * 20))


class PlatformTests(unittest.TestCase):
    def test_start_refuses_cleanly_without_af_packet(self):
        manager = CaptureManager(StubStore())
        original = capture_mod.capture_supported
        capture_mod.capture_supported = lambda: False
        try:
            with self.assertRaises(RuntimeError) as ctx:
                manager.start("A", "S", "P", "eth0", "SPAN")
            self.assertIn("requires Linux", str(ctx.exception))
            self.assertIn("Import a PCAP", str(ctx.exception))
        finally:
            capture_mod.capture_supported = original

    def test_capture_supported_matches_the_platform(self):
        self.assertEqual(capture_mod.capture_supported(), hasattr(socket, "AF_PACKET"))


if __name__ == "__main__":
    unittest.main()
