import socket
import struct
import tempfile
import unittest
from pathlib import Path

from ot_scout.parser import PacketObservation, parse_ethernet
from ot_scout.store import Store


def ethernet(dst, src, ethertype, payload):
    m = lambda s: bytes.fromhex(s.replace(":", ""))
    return m(dst) + m(src) + struct.pack("!H", ethertype) + payload


class ParserTests(unittest.TestCase):
    def test_arp(self):
        payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        payload += bytes.fromhex("001122334455") + socket.inet_aton("192.168.1.10")
        payload += b"\x00" * 6 + socket.inet_aton("192.168.1.1")
        obs = parse_ethernet(ethernet("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0x0806, payload), 1.0)
        self.assertEqual(obs.src_ip, "192.168.1.10")
        self.assertEqual(obs.app_protocol, "ARP")

    def test_modbus_tcp_and_store(self):
        ip = bytearray(20); ip[0] = 0x45; ip[9] = 6
        ip[12:16] = socket.inet_aton("10.0.0.50"); ip[16:20] = socket.inet_aton("10.0.0.10")
        tcp = struct.pack("!HHIIHHHH", 50000, 502, 0, 0, 0x5002, 1024, 0, 0)
        frame = ethernet("00:aa:bb:cc:dd:ee", "00:11:22:33:44:55", 0x0800, bytes(ip) + tcp)
        obs = parse_ethernet(frame, 2.0)
        self.assertEqual(obs.app_protocol, "MODBUS-TCP")
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "P", "test")
            store.record(session, obs); store.end_session(session)
            self.assertEqual(store.dashboard()["assets"], 2)
            self.assertEqual(store.connections()[0]["app_protocol"], "MODBUS-TCP")

    def test_visibility_detects_third_party_unicast(self):
        ip = bytearray(20); ip[0] = 0x45; ip[9] = 17
        ip[12:16] = socket.inet_aton("10.1.1.10"); ip[16:20] = socket.inet_aton("10.1.1.20")
        udp = struct.pack("!HHHH", 2000, 2001, 8, 0)
        frame = ethernet("00:aa:bb:cc:dd:ee", "00:11:22:33:44:55", 0x0800, bytes(ip) + udp)
        obs = parse_ethernet(frame, 3.0)
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "P", "test")
            for _ in range(10):
                store.record(session, obs, "00:de:ad:be:ef:00")
            self.assertEqual(store.coverage()["level"], "likely-mirror")

    def test_gateway_does_not_create_remote_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "P", "test")
            gateway = "00:11:22:33:44:55"
            endpoint = "00:aa:bb:cc:dd:ee"
            for index in range(12):
                obs = PacketObservation(10.0 + index, 100, gateway, endpoint, 0x0800,
                                        src_ip=f"203.0.113.{index + 1}", dst_ip="192.168.1.10",
                                        transport="TCP", src_port=443, dst_port=50000 + index,
                                        app_protocol="HTTPS", name_claims=[(f"203.0.113.{index + 1}", f"service-{index}.example")])
                store.record(session, obs, endpoint)
            assets = store.assets()
            self.assertEqual(len(assets), 2)
            transit = next(item for item in assets if item["mac"] == gateway)
            self.assertEqual(transit["classification"], "Gateway/transit MAC")
            self.assertEqual(transit["ips"], "")

    def test_modbus_device_identity_fingerprint_and_manual_override(self):
        ip = bytearray(20); ip[0] = 0x45; ip[9] = 6
        ip[12:16] = socket.inet_aton("10.0.0.50"); ip[16:20] = socket.inet_aton("10.0.0.10")
        objects = b"\x00\x04Acme" + b"\x05\x07PLC-100" + b"\x02\x051.2.3"
        pdu = b"\x2b\x0e\x01\x01\x00\x00\x03" + objects
        mbap = struct.pack("!HHHB", 1, 0, len(pdu) + 1, 1)
        tcp = struct.pack("!HHIIHHHH", 502, 50000, 0, 0, 0x5002, 1024, 0, 0)
        obs = parse_ethernet(ethernet("00:aa:bb:cc:dd:ee", "00:11:22:33:44:55", 0x0800,
                                      bytes(ip) + tcp + mbap + pdu), 4.0)
        claims = {(field, value) for field, value, _evidence, _confidence in obs.fingerprints}
        self.assertIn(("manufacturer", "Acme"), claims)
        self.assertIn(("model", "PLC-100"), claims)
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "P", "test")
            store.record(session, obs)
            server = next(item for item in store.assets() if item["mac"] == "00:11:22:33:44:55")
            self.assertEqual(server["manufacturer"], "Acme")
            self.assertEqual(server["model"], "PLC-100")
            self.assertEqual(server["display_type"], "Modbus device")
            updated = store.update_asset(server["id"], {"manual_type": "Safety PLC", "purdue_level": "Level 1"})
            self.assertEqual(updated["display_type"], "Safety PLC")
            self.assertEqual(updated["auto_type"], "Modbus device")
            self.assertEqual(updated["type_source"], "Assessor override")

    def test_relationships_deduplicate_bidirectional_flows(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "P", "test")
            for index, reverse in enumerate((False, True, False)):
                left_ip, right_ip = ("10.0.0.10", "10.0.0.20") if not reverse else ("10.0.0.20", "10.0.0.10")
                left_mac, right_mac = ("00:11:22:33:44:55", "00:aa:bb:cc:dd:ee") if not reverse else ("00:aa:bb:cc:dd:ee", "00:11:22:33:44:55")
                obs = PacketObservation(20.0 + index, 100, left_mac, right_mac, 0x0800,
                                        src_ip=left_ip, dst_ip=right_ip, transport="TCP",
                                        src_port=40000 + index, dst_port=502, app_protocol="MODBUS-TCP")
                store.record(session, obs)
            self.assertEqual(store.dashboard()["flows"], 3)
            relationships = store.relationships()
            self.assertEqual(len(relationships), 1)
            self.assertEqual(relationships[0]["flows"], 3)

    def test_derived_identity_is_not_counted_as_physical_asset(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "P", "test")
            real = PacketObservation(30.0, 100, "00:14:22:70:00:81", "00:aa:bb:cc:dd:ee", 0x0800,
                                     src_ip="192.168.1.1", dst_ip="192.168.1.2", transport="UDP", app_protocol="UDP")
            virtual = PacketObservation(31.0, 60, "02:14:22:70:00:8f", "ff:ff:ff:ff:ff:ff", 0x88cc,
                                        transport="OTHER", app_protocol="OTHER")
            store.record(session, real)
            for _ in range(12):
                store.record(session, virtual)
            identities = store.assets()
            derived = next(item for item in identities if item["mac"] == "02:14:22:70:00:8f")
            self.assertFalse(derived["physical_asset"])
            self.assertEqual(derived["packets"], 12)
            self.assertEqual(store.dashboard()["identities"], 3)
            self.assertEqual(store.dashboard()["assets"], 2)

    def test_home_capture_shape_counts_four_physical_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("Home", "Home", "Ethernet", "eth0")
            gateway, laptop = "00:14:22:70:00:81", "00:14:22:70:00:21"
            for index in range(12):
                store.record(session, PacketObservation(40 + index, 100, gateway, laptop, 0x0800,
                    src_ip=f"203.0.113.{index + 1}", dst_ip="192.168.1.168", transport="TCP",
                    src_port=443, dst_port=50000 + index, app_protocol="HTTPS"), laptop)
            observations = [
                PacketObservation(60, 100, "00:1a:a1:70:00:01", laptop, 0x0800,
                                  src_ip="192.168.1.65", dst_ip="192.168.1.168", transport="TCP", app_protocol="TCP"),
                PacketObservation(61, 60, "00:14:22:70:00:61", "ff:ff:ff:ff:ff:ff", 0x88cc, app_protocol="OTHER"),
                PacketObservation(62, 60, "02:14:22:70:00:8e", "ff:ff:ff:ff:ff:ff", 0x88cc, app_protocol="OTHER"),
                PacketObservation(63, 60, "02:14:22:70:00:8f", "ff:ff:ff:ff:ff:ff", 0x88cc, app_protocol="OTHER"),
            ]
            for observation in observations:
                store.record(session, observation, laptop)
            summary = store.dashboard()
            self.assertEqual(summary["identities"], 6)
            self.assertEqual(summary["assets"], 4)

    def test_known_gateway_keeps_direct_ip_and_suppresses_routed_ips(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            store.vendors.prefixes["001AA1"] = "Cisco Systems"
            session = store.begin_session("Home", "Home", "Wi-Fi", "wlan0")
            gateway = "00:1a:a1:70:00:0d"
            laptop = "00:14:22:70:00:21"
            store.record(session, PacketObservation(70, 60, gateway, "ff:ff:ff:ff:ff:ff", 0x0806,
                src_ip="192.168.4.1", dst_ip="192.168.4.20", app_protocol="ARP"), laptop)
            for index, remote in enumerate(("8.8.8.8", "1.1.1.1")):
                store.record(session, PacketObservation(71 + index, 100, gateway, laptop, 0x0800,
                    src_ip=remote, dst_ip="192.168.4.20", transport="TCP", src_port=443,
                    dst_port=51000 + index, app_protocol="HTTPS"), laptop)
            item = next(asset for asset in store.assets() if asset["mac"] == gateway)
            self.assertEqual(item["classification"], "Gateway/transit MAC")
            self.assertEqual(item["ips"], "192.168.4.1")
            self.assertEqual(item["suppressed_transit_ips"], 2)
            self.assertEqual(item["display_type"], "Gateway/router")
            self.assertEqual(item["interfaces"], "wlan0")

    def test_vendor_based_iot_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            store.vendors.prefixes["001122"] = "Wyze Labs Inc."
            session = store.begin_session("A", "S", "P", "eth7")
            store.record(session, PacketObservation(80, 60, "00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", 0x0806,
                src_ip="10.0.0.30", dst_ip="10.0.0.1", app_protocol="ARP"))
            item = next(asset for asset in store.assets() if asset["mac"] == "00:11:22:33:44:55")
            self.assertEqual(item["display_type"], "Camera / IoT device")
            self.assertEqual(item["type_confidence"], 65)

    def test_derived_identity_precedes_passive_role_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "P", "eth0")
            store.record(session, PacketObservation(90, 60, "00:14:22:70:00:81", "ff:ff:ff:ff:ff:ff", 0x88cc,
                app_protocol="OTHER"))
            store.record(session, PacketObservation(91, 60, "02:14:22:70:00:8f", "ff:ff:ff:ff:ff:ff", 0x88cc,
                app_protocol="OTHER", fingerprints=[("role", "Network infrastructure", "LLDP capabilities", 90)]))
            item = next(asset for asset in store.assets() if asset["mac"] == "02:14:22:70:00:8f")
            self.assertEqual(item["display_type"], "Virtual interface")
            self.assertFalse(item["physical_asset"])

    def test_broadcast_traffic_is_separate_from_unicast_relationships(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "Wireless", "wlan0")
            source = "00:11:22:33:44:55"
            peer = "00:aa:bb:cc:dd:ee"
            store.record(session, PacketObservation(100, 100, source, peer, 0x0800,
                src_ip="10.0.0.10", dst_ip="10.0.0.20", transport="TCP", src_port=40000,
                dst_port=502, app_protocol="MODBUS-TCP"))
            store.record(session, PacketObservation(100.5, 100, peer, source, 0x0800,
                src_ip="10.0.0.20", dst_ip="10.0.0.10", transport="TCP", src_port=502,
                dst_port=40000, app_protocol="MODBUS-TCP"))
            store.record(session, PacketObservation(101, 100, source, "ff:ff:ff:ff:ff:ff", 0x0800,
                src_ip="10.0.0.10", dst_ip="255.255.255.255", transport="UDP", src_port=5353,
                dst_port=5353, app_protocol="MDNS"))
            relationships = store.relationships()
            discovery = store.discovery_traffic()
            self.assertEqual(len(relationships), 1)
            self.assertEqual(relationships[0]["interfaces"], "wlan0")
            self.assertEqual(relationships[0]["category"], "Local asset-to-asset")
            self.assertEqual(len(discovery), 1)
            self.assertEqual(discovery[0]["protocol"], "MDNS")
            self.assertEqual(store.dashboard()["discovery_groups"], 1)


if __name__ == "__main__":
    unittest.main()


class DurationTests(unittest.TestCase):
    def test_session_duration_is_reported_and_exported(self):
        from ot_scout.store import duration_seconds, format_duration
        self.assertEqual(duration_seconds("2026-09-02T15:00:00+00:00", "2026-09-02T15:05:12+00:00"), 312)
        self.assertEqual(format_duration(312), "5:12")
        self.assertEqual(format_duration(3725), "1:02:05")
        self.assertEqual(format_duration(None), "")
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "P", "test")
            open_session = store.sessions()[0]
            self.assertIsNone(open_session["ended_at"])
            self.assertGreaterEqual(open_session["duration_seconds"], 0)
            store.end_session(session)
            closed = store.sessions()[0]
            self.assertIsNotNone(closed["ended_at"])
            self.assertEqual(closed["duration"], format_duration(closed["duration_seconds"]))
            import json
            exported = json.loads(store.json_export())
            self.assertIn("duration_seconds", exported["sessions"][0])

    def test_capture_status_reports_elapsed_seconds(self):
        from ot_scout.capture import CaptureManager
        with tempfile.TemporaryDirectory() as tmp:
            capture = CaptureManager(Store(Path(tmp) / "test.db"))
            self.assertIsNone(capture.status()["elapsed_seconds"])
            capture.started_at = 1000.0
            capture.stopped_at = 1312.0
            self.assertEqual(capture.status()["elapsed_seconds"], 312)


class ReportTests(unittest.TestCase):
    def _store_with_traffic(self, tmp):
        store = Store(Path(tmp) / "test.db")
        session = store.begin_session("Plant A", "Site 1", "Cell switch SPAN", "eth0", "live", "Configured SPAN/mirror")
        ip = bytearray(20); ip[0] = 0x45; ip[9] = 6
        ip[12:16] = socket.inet_aton("10.0.0.50"); ip[16:20] = socket.inet_aton("10.0.0.10")
        tcp = struct.pack("!HHIIHHHH", 50000, 502, 0, 0, 0x5002, 1024, 0, 0)
        frame = ethernet("00:aa:bb:cc:dd:ee", "00:11:22:33:44:55", 0x0800, bytes(ip) + tcp)
        for _ in range(12):
            store.record(session, parse_ethernet(frame, 2.0), local_mac="00:00:00:00:00:01")
        store.end_session(session)
        return store

    def test_report_builds_valid_docx_from_store(self):
        import zipfile, io
        from ot_scout.report import build_report, collect
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store_with_traffic(tmp)
            raw = build_report(collect(store), {"prepared_for": "Client & Co", "prepared_by": "Tester", "sanitize": True})
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                names = set(z.namelist())
                self.assertIn("word/document.xml", names)
                document = z.read("word/document.xml").decode("utf-8")
            import xml.dom.minidom
            xml.dom.minidom.parseString(document)  # well-formed
            self.assertIn("Client &amp; Co", document)
            self.assertIn("Modbus/TCP", document)
            self.assertIn("00:11:22:XX:XX:55", document)
            self.assertNotIn("00:11:22:33:44:55", document)
            self.assertIn("Industrial protocols observed", document)

    def test_report_builds_from_json_export_without_coverage(self):
        import json
        from ot_scout.report import build_report
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store_with_traffic(tmp)
            data = json.loads(store.json_export())
            self.assertNotIn("coverage", data)
            raw = build_report(data, {})
            self.assertGreater(len(raw), 5000)

    def test_report_handles_empty_store(self):
        from ot_scout.report import build_report, collect
        with tempfile.TemporaryDirectory() as tmp:
            raw = build_report(collect(Store(Path(tmp) / "test.db")), {})
            self.assertGreater(len(raw), 5000)


def _ipv4(src, dst, proto, payload):
    ip = bytearray(20); ip[0] = 0x45; ip[9] = proto
    ip[2:4] = struct.pack("!H", 20 + len(payload))
    ip[12:16] = socket.inet_aton(src); ip[16:20] = socket.inet_aton(dst)
    return bytes(ip) + payload


def _tcp(sport, dport, payload):
    return struct.pack("!HHIIHHHH", sport, dport, 1, 1, 0x5018, 1024, 0, 0) + payload


class IndustrialDecoderTests(unittest.TestCase):
    def test_dnp3_crc_reference_value(self):
        from ot_scout.parser import _dnp3_crc
        self.assertEqual(_dnp3_crc(b"123456789"), 0xEA82)  # CRC-16/DNP check value

    def test_dnp3_unsolicited_response_identifies_outstation(self):
        from ot_scout.parser import _dnp3_crc
        header = bytes([0x05, 0x64, 0x0A, 0x44]) + struct.pack("<HH", 3, 4)  # DIR=0 (from outstation), dst 3, src 4
        link = header + struct.pack("<H", _dnp3_crc(header))
        app = bytes([0xC0, 0xC0, 0x82, 0x90, 0x00])  # transport FIR|FIN, app ctrl, unsolicited response, IIN1 restart+need time
        frame = ethernet("00:aa:bb:cc:dd:ee", "00:11:22:33:44:55", 0x0800, _ipv4("10.1.1.20", "10.1.1.5", 6, _tcp(20000, 51000, link + app + b"\x00\x00")))
        obs = parse_ethernet(frame, 1.0)
        self.assertEqual(obs.app_protocol, "DNP3")
        fp = dict((f[0], f[1]) for f in obs.fingerprints)
        self.assertEqual(fp["role"], "DNP3 outstation")
        self.assertEqual(fp["dnp3_link_address"], "4")
        self.assertEqual(fp["dnp3_function"], "Unsolicited response")
        self.assertIn("device restart", fp["dnp3_iin"])

    def test_dnp3_bad_crc_yields_no_claims(self):
        header = bytes([0x05, 0x64, 0x0A, 0x44]) + struct.pack("<HH", 3, 4) + b"\x00\x00"
        frame = ethernet("00:aa:bb:cc:dd:ee", "00:11:22:33:44:55", 0x0800, _ipv4("10.1.1.20", "10.1.1.5", 6, _tcp(20000, 51000, header + b"\xc0\xc0\x82")))
        self.assertEqual(parse_ethernet(frame, 1.0).fingerprints, [])

    def test_s7_cotp_connect_confirm_reports_tsap(self):
        cotp = bytes([0x11, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x02, 0x02])
        tpkt = bytes([3, 0]) + struct.pack("!H", 4 + len(cotp)) + cotp
        frame = ethernet("00:aa:bb:cc:dd:ee", "00:1c:06:11:22:33", 0x0800, _ipv4("192.168.0.1", "192.168.0.50", 6, _tcp(102, 40000, tpkt)))
        fp = dict((f[0], f[1]) for f in parse_ethernet(frame, 1.0).fingerprints)
        self.assertEqual(fp["role"], "Siemens S7 controller")
        self.assertIn("rack 0 slot 2", fp["s7_dst_tsap"])

    def test_s7_szl_0011_response_extracts_order_number_and_firmware(self):
        def entry(index, mlfb, bgtyp, ausbg, ausbe):
            return struct.pack("!H", index) + mlfb.ljust(20).encode() + struct.pack("!HHH", bgtyp, ausbg, ausbe)
        entries = entry(1, "6ES7 315-2EH14-0AB0", 0x2001, 0x0003, 0x0001) + entry(7, "6ES7 315-2EH14-0AB0", 0x2001, 0x5603, 0x0207)
        szl = bytes([0xFF, 0x09]) + struct.pack("!H", 8 + len(entries)) + struct.pack("!HHHH", 0x0011, 0x0000, 28, 2) + entries
        params = bytes([0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00])
        s7 = bytes([0x32, 0x07, 0x00, 0x00, 0x00, 0x01]) + struct.pack("!HH", len(params), len(szl)) + params + szl
        cotp = bytes([0x02, 0xF0, 0x80])
        tpkt = bytes([3, 0]) + struct.pack("!H", 4 + len(cotp) + len(s7)) + cotp + s7
        frame = ethernet("00:aa:bb:cc:dd:ee", "00:1c:06:11:22:33", 0x0800, _ipv4("192.168.0.1", "192.168.0.50", 6, _tcp(102, 40000, tpkt)))
        obs = parse_ethernet(frame, 1.0)
        fp = dict((f[0], f[1]) for f in obs.fingerprints)
        self.assertEqual(fp["model"], "6ES7 315-2EH14-0AB0")
        self.assertEqual(fp["firmware"], "V3.2.7")
        self.assertEqual(fp["role"], "Siemens S7 controller")
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "P", "test")
            store.record(session, obs)
            plc = next(a for a in store.assets() if a["mac"] == "00:1c:06:11:22:33")
            self.assertEqual(plc["model"], "6ES7 315-2EH14-0AB0")
            self.assertEqual(plc["firmware"], "V3.2.7")
            self.assertEqual(plc["auto_type"], "Siemens S7 controller")

    def test_profinet_dcp_identify_response_names_the_device(self):
        def block(option, suboption, body):
            data = struct.pack("!BBH", option, suboption, len(body)) + body
            return data + (b"\x00" if len(body) & 1 else b"")
        blocks = (block(2, 1, b"\x00\x00" + b"S7-1500") + block(2, 2, b"\x00\x00" + b"plc-line1") +
                  block(2, 3, b"\x00\x00" + struct.pack("!HH", 0x002A, 0x010D)) + block(2, 4, b"\x00\x00" + b"\x02\x00") +
                  block(1, 2, b"\x00\x01" + socket.inet_aton("192.168.10.5") + socket.inet_aton("255.255.255.0") + socket.inet_aton("192.168.10.1")))
        dcp = struct.pack("!HBBIHH", 0xFEFF, 0x05, 0x01, 0x1234, 0, len(blocks)) + blocks
        frame = ethernet("00:aa:bb:cc:dd:ee", "28:63:36:aa:bb:cc", 0x8892, dcp)
        obs = parse_ethernet(frame, 1.0)
        self.assertEqual(obs.app_protocol, "PROFINET-DCP")
        self.assertEqual(obs.source_name, "plc-line1")
        self.assertEqual(obs.src_ip, "192.168.10.5")
        fp = dict((f[0], f[1]) for f in obs.fingerprints)
        self.assertEqual(fp["role"], "Profinet IO controller")
        self.assertEqual(fp["model"], "S7-1500")
        self.assertEqual(fp["manufacturer"], "Siemens AG")
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "P", "test")
            store.record(session, obs)
            plc = next(a for a in store.assets() if a["mac"] == "28:63:36:aa:bb:cc")
            self.assertEqual(plc["name"], "plc-line1")
            self.assertEqual(plc["ips"], "192.168.10.5")
            self.assertEqual(plc["manufacturer"], "Siemens AG")

    def test_profinet_cyclic_frame_is_tagged_rt(self):
        frame = ethernet("00:aa:bb:cc:dd:ee", "28:63:36:aa:bb:cc", 0x8100, struct.pack("!HH", 0xC000, 0x8892) + struct.pack("!H", 0x8000) + b"\x00" * 40)
        obs = parse_ethernet(frame, 1.0)
        self.assertEqual(obs.vlan, 0)
        self.assertEqual(obs.app_protocol, "PROFINET-RT")


class SiteValidationTests(unittest.TestCase):
    def test_site_checklist_and_leg_coverage(self):
        import json
        from ot_scout.report import build_report, collect
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            site = store.save_site({"assessment": "A", "name": "WTP-1", "facility_type": "Water treatment"})
            self.assertEqual(site["checklist_total"], len(Store.CHECKLIST_ITEMS))
            self.assertEqual(site["checklist_complete"], 0)
            site = store.save_checklist_item(site["id"], "walkdown", {"status": "Complete", "evidence": "Photos 1-12"})
            self.assertEqual(site["checklist_complete"], 1)
            with self.assertRaises(ValueError):
                store.save_checklist_item(site["id"], "walkdown", {"status": "Done"})
            session = store.begin_session("A", "WTP-1", "Control room SPAN", "eth0", "live", "Configured SPAN/mirror")
            ip = bytearray(20); ip[0] = 0x45; ip[9] = 6
            ip[12:16] = socket.inet_aton("10.0.0.50"); ip[16:20] = socket.inet_aton("10.0.0.10")
            tcp = struct.pack("!HHIIHHHH", 50000, 502, 0, 0, 0x5002, 1024, 0, 0)
            store.record(session, parse_ethernet(ethernet("00:aa:bb:cc:dd:ee", "00:11:22:33:44:55", 0x0800, bytes(ip) + tcp), 2.0))
            store.end_session(session)
            site = store.save_leg(site["id"], {"name": "Control room LAN", "evidence_source": "Configured SPAN/mirror", "collection_point": "Control room SPAN", "status": "Collected"})
            site = store.save_leg(site["id"], {"name": "Remote lift stations radio", "purdue_level": "Level 1"})
            legs = {l["name"]: l for l in site["legs"]}
            self.assertEqual(legs["Control room LAN"]["coverage"]["sessions"], 1)
            self.assertEqual(legs["Control room LAN"]["coverage"]["assets_seen"], 2)
            self.assertEqual(legs["Remote lift stations radio"]["coverage"]["sessions"], 0)
            self.assertEqual(site["legs_with_evidence"], 1)
            data = json.loads(store.json_export())
            self.assertEqual(len(data["sites"]), 1)
            raw = build_report(collect(store), {})
            import zipfile, io
            document = zipfile.ZipFile(io.BytesIO(raw)).read("word/document.xml").decode()
            self.assertIn("Coverage by network leg", document)
            self.assertIn("Network legs without an evidence source", document)
            self.assertIn("Remote lift stations radio", document)
            store.delete_leg(legs["Remote lift stations radio"]["id"])
            self.assertEqual(len(store.site(site["id"])["legs"]), 1)
            store.delete_site(site["id"])
            self.assertEqual(store.sites(), [])


class InventoryHygieneTests(unittest.TestCase):
    def test_generic_and_self_referential_names_are_ignored(self):
        from ot_scout.store import informative_name
        self.assertFalse(informative_name("localhost.local", "00:14:22:70:00:31"))
        self.assertFalse(informative_name("00:14:22:70:00:51-0.local", "00:14:22:70:00:51"))
        self.assertFalse(informative_name("001422700041.local", "00:14:22:70:00:41"))
        self.assertFalse(informative_name("A1B2C3D4E5F60718293A4B5C.local", "00:22:6c:28:45:79"))
        self.assertFalse(informative_name("192-168-4-22.local", "00:14:22:70:00:71"))
        self.assertTrue(informative_name("gw-lab-a1.local", "00:1a:a1:70:00:0d"))
        self.assertTrue(informative_name("plc-line1", "28:63:36:aa:bb:cc"))
        self.assertTrue(informative_name("ews-lab-01.local", "00:14:22:70:00:11"))

    def test_adjacent_mac_without_ip_is_secondary_interface(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            store.vendors.prefixes["001AA1"] = "Cisco Systems"
            session = store.begin_session("A", "S", "P", "test")
            payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("001aa170000d") + socket.inet_aton("192.168.4.1") + b"\x00" * 6 + socket.inet_aton("192.168.4.61")
            store.record(session, parse_ethernet(ethernet("ff:ff:ff:ff:ff:ff", "00:1a:a1:70:00:0d", 0x0806, payload), 1.0))
            # second radio of the same access point: adjacent MAC, no IP, only a non-IP frame
            store.record(session, parse_ethernet(ethernet("01:80:c2:00:00:0e", "00:1a:a1:70:00:06", 0x88CC, b"\x00\x00"), 1.0))
            # unrelated device from the same vendor far away in MAC space keeps its own identity
            payload2 = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("001aa171000e") + socket.inet_aton("192.168.4.39") + b"\x00" * 6 + socket.inet_aton("192.168.4.1")
            store.record(session, parse_ethernet(ethernet("ff:ff:ff:ff:ff:ff", "00:1a:a1:71:00:0e", 0x0806, payload2), 1.0))
            # two Siemens-style controllers with sequential MACs: one silent apart from LLDP must stay a physical asset
            payload3 = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("001122000001") + socket.inet_aton("10.0.1.10") + b"\x00" * 6 + socket.inet_aton("10.0.1.1")
            store.record(session, parse_ethernet(ethernet("ff:ff:ff:ff:ff:ff", "00:11:22:00:00:01", 0x0806, payload3), 1.0))
            store.record(session, parse_ethernet(ethernet("01:80:c2:00:00:0e", "00:11:22:00:00:02", 0x88CC, b"\x00\x00"), 1.0))
            by_mac = {a["mac"]: a for a in store.assets()}
            self.assertTrue(by_mac["00:11:22:00:00:02"]["physical_asset"])
            self.assertEqual(by_mac["00:1a:a1:70:00:06"]["classification"], "Likely secondary interface")
            self.assertFalse(by_mac["00:1a:a1:70:00:06"]["physical_asset"])
            self.assertTrue(by_mac["00:1a:a1:70:00:0d"]["physical_asset"])
            self.assertTrue(by_mac["00:1a:a1:71:00:0e"]["physical_asset"])
            self.assertEqual(store.dashboard()["assets"], 4)

    def test_minority_subnet_observation(self):
        from ot_scout.report import Analysis
        assets = [{"physical_asset": True, "ips": f"192.168.4.{i}", "name": f"dev{i}", "packets": 1} for i in range(5)]
        assets.append({"physical_asset": True, "ips": "192.168.5.250", "name": "stray", "packets": 1})
        a = Analysis({"assets": assets, "sessions": [{"packets": 10, "third_party_unicast": 0, "access_method": "Configured SPAN/mirror", "started_at": "2026-09-02T00:00:00+00:00", "ended_at": "2026-09-02T00:05:00+00:00"}]}, False)
        self.assertIn("192.168.5.0/24", a.minority_subnets)
        self.assertTrue(any("Multiple IPv4 subnets" in f["title"] for f in a.findings))


class FindingsRegisterTests(unittest.TestCase):
    def test_register_crud_import_and_report_rollup(self):
        import io, json, zipfile
        from ot_scout.report import Analysis, build_report, collect
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "P", "eth0", "live", "Unconfirmed access port")
            payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("001122334455") + socket.inet_aton("192.168.1.10") + b"\x00" * 6 + socket.inet_aton("192.168.1.1")
            store.record(session, parse_ethernet(ethernet("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0x0806, payload), 1.0))
            store.end_session(session)
            # drafts exist before anything is in the register, and the report falls back to them
            drafts = Analysis(collect(store), False).drafts
            self.assertTrue(any(d["id"] == "OBS-01" for d in drafts))
            doc = zipfile.ZipFile(io.BytesIO(build_report(collect(store), {}))).read("word/document.xml").decode()
            self.assertIn("Observation summary", doc)
            # import drafts, second import adds nothing
            added = store.import_draft_findings(drafts)
            self.assertEqual(added, len(drafts))
            self.assertEqual(store.import_draft_findings(drafts), 0)
            reg = store.findings()
            self.assertEqual(reg[0]["status"], "Draft")
            self.assertEqual(reg[0]["source"], "OT Scout draft")
            # assessor validates one, rejects one, adds a deficiency
            store.save_finding({"id": reg[0]["id"], "status": "Validated", "horizon": "Immediate / quick win", "owner": "Plant IT"})
            pos = next(f for f in reg if f["kind"] == "Positive observation")
            store.save_finding({"id": pos["id"], "status": "Rejected"})
            fnd = store.save_finding({"title": "Flat network between control room and office", "kind": "Control deficiency", "rating": "High priority", "horizon": "3-12 months", "owner": "Network owner", "status": "Validated"})
            self.assertEqual(fnd["ref"], "FND-01")
            with self.assertRaises(ValueError):
                store.save_finding({"title": "x", "rating": "Severe"})
            data = json.loads(store.json_export())
            self.assertIn("findings", data)
            doc = zipfile.ZipFile(io.BytesIO(build_report(collect(store), {}))).read("word/document.xml").decode()
            self.assertIn("Findings summary", doc)
            self.assertIn("FND-01", doc)
            self.assertIn("Rejected and excluded", doc)
            self.assertIn("Roadmap is rolled up", doc)
            self.assertIn("FND-01 Flat network", doc)
            store.delete_finding(fnd["id"])
            self.assertFalse(any(f["ref"] == "FND-01" for f in store.findings()))


class ZoneConduitTests(unittest.TestCase):
    def _flow(self, store, session, src_mac, src, dst_mac, dst, dport):
        ip = bytearray(20); ip[0] = 0x45; ip[9] = 6
        ip[12:16] = socket.inet_aton(src); ip[16:20] = socket.inet_aton(dst)
        tcp = struct.pack("!HHIIHHHH", 50000, dport, 0, 0, 0x5002, 1024, 0, 0)
        store.record(session, parse_ethernet(ethernet(dst_mac, src_mac, 0x0800, bytes(ip) + tcp), 2.0))

    def test_zone_pairs_crossings_and_conduit_decisions(self):
        import io, zipfile
        from ot_scout.report import Analysis, build_report, collect
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "SPAN", "eth0", "live", "Configured SPAN/mirror")
            plc, hmi, erp = "00:11:22:00:00:01", "00:11:22:00:00:02", "00:11:22:00:00:03"
            self._flow(store, session, hmi, "10.0.1.20", plc, "10.0.1.10", 502)
            self._flow(store, session, plc, "10.0.1.10", hmi, "10.0.1.20", 50000)
            self._flow(store, session, erp, "10.0.5.5", plc, "10.0.1.10", 502)
            self._flow(store, session, plc, "10.0.1.10", erp, "10.0.5.5", 50000)
            self._flow(store, session, hmi, "10.0.1.20", "00:aa:bb:cc:dd:ee", "8.8.8.8", 443)
            store.end_session(session)
            ids = {a["mac"]: a["id"] for a in store.assets()}
            store.update_asset(ids[plc], {"purdue_level": "Level 1"})
            store.update_asset(ids[hmi], {"purdue_level": "Level 2"})
            store.update_asset(ids[erp], {"purdue_level": "Level 4"})
            by_pair = {tuple(sorted((r["level_a"], r["level_b"]))): r for r in store.relationships()}
            self.assertEqual(by_pair[("Level 1", "Level 2")]["crossing"], "Level 1 to Level 2")
            self.assertEqual(by_pair[("Level 1", "Level 4")]["crossing"], "OT to enterprise (bypasses industrial DMZ)")
            self.assertEqual(by_pair[("External", "Level 2")]["crossing"], "OT to external/internet")
            self.assertEqual(Store.crossing_kind("Level 3", "Industrial DMZ"), "OT to industrial DMZ")
            self.assertEqual(Store.crossing_kind("Industrial DMZ", "Level 5"), "Industrial DMZ to enterprise")
            self.assertEqual(Store.crossing_kind("Level 2", "Level 2"), "")
            r = by_pair[("Level 1", "Level 4")]
            store.save_conduit(r["key_a"], r["key_b"], {"decision": "Unexpected", "purpose": "ERP polling PLC directly"})
            with self.assertRaises(ValueError):
                store.save_conduit(r["key_a"], r["key_b"], {"decision": "Fine"})
            rels = store.relationships()
            self.assertEqual(next(x for x in rels if x["key_a"] == r["key_a"] and x["key_b"] == r["key_b"])["decision"], "Unexpected")
            z = store.zone_summary()
            self.assertEqual(z["assigned"], 3)
            self.assertEqual(z["unexpected"], 1)
            self.assertEqual(z["unreviewed_crossings"], 2)
            self.assertEqual(z["levels"]["Level 1"]["assets"], 1)
            svg = store.purdue_svg()
            self.assertTrue(svg.startswith("<svg") and "Level 1" in svg and "External" in svg and "→ Level 1" in svg)
            a = Analysis(collect(store), False)
            titles = [f["title"] for f in a.findings]
            self.assertTrue(any("marked unexpected" in t for t in titles))
            self.assertTrue(any("not yet reviewed" in t for t in titles))
            doc = zipfile.ZipFile(io.BytesIO(build_report(collect(store), {}))).read("word/document.xml").decode()
            self.assertIn("Purdue zone assignment and boundary crossings", doc)
            self.assertIn("bypasses industrial DMZ", doc)


class LevelSuggestionTests(unittest.TestCase):
    def test_protocol_role_suggests_levels_and_accept_records_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "SPAN", "eth0", "live", "Configured SPAN/mirror")
            plc, hmi, laptop, gw = "00:1c:06:00:00:01", "00:d0:c9:00:00:10", "00:d0:c9:00:00:20", "00:1a:a1:70:00:11"
            def flow(sm, src, dm, dst, dport):
                ip = bytearray(20); ip[0] = 0x45; ip[9] = 6
                ip[12:16] = socket.inet_aton(src); ip[16:20] = socket.inet_aton(dst)
                tcp = struct.pack("!HHIIHHHH", 50000, dport, 0, 0, 0x5002, 1024, 0, 0)
                store.record(session, parse_ethernet(ethernet(dm, sm, 0x0800, bytes(ip) + tcp), 2.0))
            flow(hmi, "10.0.2.20", plc, "10.0.1.10", 502); flow(plc, "10.0.1.10", hmi, "10.0.2.20", 50000)
            flow(laptop, "10.0.9.5", gw, "10.0.9.1", 443); flow(laptop, "10.0.9.5", gw, "10.0.9.1", 53)
            for i in range(9):  # make the gateway carry many source IPs so it is classified as transit
                flow(gw, f"52.1.1.{i}", laptop, "10.0.9.5", 50001)
            store.end_session(session)
            by = {a["mac"]: a for a in store.assets()}
            self.assertEqual((by[plc]["suggested_level"], by[plc]["level_confidence"]), ("Level 1", 85))
            self.assertEqual(by[hmi]["suggested_level"], "Level 2")
            self.assertEqual(by[gw]["suggested_level"], "")
            self.assertEqual(by[plc]["purdue_level"], "")
            applied = store.accept_suggested_levels()
            self.assertGreaterEqual(applied, 2)
            by = {a["mac"]: a for a in store.assets()}
            self.assertEqual(by[plc]["purdue_level"], "Level 1")
            self.assertEqual(by[plc]["purdue_source"], "Suggested")
            store.update_asset(by[hmi]["id"], {"purdue_level": "Level 3"})
            by = {a["mac"]: a for a in store.assets()}
            self.assertEqual(by[hmi]["purdue_source"], "Assessor")
            self.assertEqual(store.accept_suggested_levels(), 0)  # nothing left without a level
            z = store.zone_summary()
            self.assertEqual(z["assigned_by_assessor"], 1)
            self.assertGreaterEqual(z["assigned_from_suggestion"], 1)
            store.update_asset(by[plc]["id"], {"manual_type": "Safety PLC"})
            self.assertEqual(next(a for a in store.assets() if a["mac"] == plc)["level_confidence"], 90)


class ExternalMergeTests(unittest.TestCase):
    def test_external_service_with_many_ips_is_one_relationship(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            session = store.begin_session("A", "S", "P", "eth0")
            # DNS answer maps several public IPs to one name
            def dns_answer(name, ip):
                q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
                hdr = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
                ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
                payload = hdr + q + struct.pack("!HH", 1, 1) + ans
                ip_h = bytearray(20); ip_h[0] = 0x45; ip_h[9] = 17
                ip_h[12:16] = socket.inet_aton("10.0.0.1"); ip_h[16:20] = socket.inet_aton("10.0.0.5")
                udp = struct.pack("!HHHH", 53, 40000, 8 + len(payload), 0)
                return ethernet("00:11:22:33:44:55", "00:aa:bb:cc:dd:ee", 0x0800, bytes(ip_h) + udp + payload)
            for ip in ("35.1.1.1", "35.1.1.2", "35.1.1.3"):
                store.record(session, parse_ethernet(dns_answer("connectivity-check.ubuntu.com", ip), 1.0))
                ip_h = bytearray(20); ip_h[0] = 0x45; ip_h[9] = 6
                ip_h[12:16] = socket.inet_aton("10.0.0.5"); ip_h[16:20] = socket.inet_aton(ip)
                tcp = struct.pack("!HHIIHHHH", 40001, 80, 0, 0, 0x5002, 1024, 0, 0)
                store.record(session, parse_ethernet(ethernet("00:aa:bb:cc:dd:ee", "00:11:22:33:44:55", 0x0800, bytes(ip_h) + tcp), 1.0))
            store.end_session(session)
            rels = [r for r in store.relationships() if r["endpoint_b"] == "connectivity-check.ubuntu.com" or r["endpoint_a"] == "connectivity-check.ubuntu.com"]
            self.assertEqual(len(rels), 1)
            self.assertEqual(rels[0]["external_ips"], 3)
            self.assertEqual(rels[0]["level_b"] if rels[0]["endpoint_b"].startswith("connectivity") else rels[0]["level_a"], "External")
            store.save_conduit(rels[0]["key_a"], rels[0]["key_b"], {"decision": "Tolerated", "purpose": "OS connectivity check"})
            self.assertEqual([r for r in store.relationships() if r["key_a"] == rels[0]["key_a"] and r["key_b"] == rels[0]["key_b"]][0]["decision"], "Tolerated")


class InfrastructureLevelTests(unittest.TestCase):
    def test_gateway_is_infrastructure_not_unassigned(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            store.vendors.prefixes["001AA1"] = "Cisco Systems"
            session = store.begin_session("A", "S", "P", "eth0")
            laptop, gw = "00:d0:c9:00:00:20", "00:1a:a1:70:00:11"
            def flow(sm, src, dm, dst, dport):
                ip = bytearray(20); ip[0] = 0x45; ip[9] = 17
                ip[12:16] = socket.inet_aton(src); ip[16:20] = socket.inet_aton(dst)
                store.record(session, parse_ethernet(ethernet(dm, sm, 0x0800, bytes(ip) + struct.pack("!HHHH", 40000, dport, 8, 0)), 2.0))
            flow(laptop, "192.168.4.61", gw, "192.168.4.1", 53); flow(gw, "192.168.4.1", laptop, "192.168.4.61", 40000)
            flow(laptop, "192.168.4.61", gw, "52.1.1.1", 443)
            store.end_session(session)
            rels = store.relationships()
            local = next(r for r in rels if "External" not in (r["level_a"], r["level_b"]))
            self.assertEqual(sorted((local["level_a"], local["level_b"])), ["Network infrastructure", "Unassigned"])
            self.assertEqual(local["crossing"], "")
            z = store.zone_summary()
            self.assertEqual(z["infrastructure"], 1)
            self.assertEqual(z["levels"]["Network infrastructure"]["assets"], 1)
            gw_id = next(a["id"] for a in store.assets() if a["mac"] == gw)
            store.update_asset(gw_id, {"purdue_level": "Level 3"})
            local = next(r for r in store.relationships() if "External" not in (r["level_a"], r["level_b"]))
            self.assertIn("Level 3", (local["level_a"], local["level_b"]))


class DocumentedAssetTests(unittest.TestCase):
    def test_template_import_upsert_merge_and_report(self):
        import io, json, zipfile
        from ot_scout.report import Analysis, build_report, collect
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "test.db")
            result = store.import_assets_csv(store.asset_template_csv())
            self.assertEqual((result["created"], result["updated"], result["errors"]), (2, 0, []))
            by_name = {a["name"]: a for a in store.assets()}
            plc = by_name["PLC-101 Filter gallery"]
            self.assertEqual(plc["classification"], "Documented, not observed")
            self.assertEqual((plc["purdue_level"], plc["purdue_source"], plc["support_status"]), ("Level 1", "Assessor", "End of support"))
            self.assertEqual(plc["ips"], "10.10.1.10")
            self.assertTrue(by_name["RTU-7 Lift station 7"]["mac"].startswith("manual:"))
            # re-import updates instead of duplicating
            result = store.import_assets_csv(store.asset_template_csv())
            self.assertEqual((result["created"], result["updated"]), (0, 2))
            # bad rows are reported, good rows still land
            bad = b"name,mac,purdue_level\nGood,00:aa:bb:cc:dd:01,Level 2\nBad level,00:aa:bb:cc:dd:02,Layer 9\nBad mac,zz:zz,Level 1\n"
            result = store.import_assets_csv(bad)
            self.assertEqual(result["created"], 1)
            self.assertEqual(len(result["errors"]), 2)
            # passive evidence for the documented MAC lands on the same asset
            session = store.begin_session("A", "S", "P", "eth0")
            payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("001c06123456") + socket.inet_aton("10.10.1.10") + b"\x00" * 6 + socket.inet_aton("10.10.1.1")
            store.record(session, parse_ethernet(ethernet("ff:ff:ff:ff:ff:ff", "00:1c:06:12:34:56", 0x0806, payload), 1.0))
            plc = next(a for a in store.assets() if a["mac"] == "00:1c:06:12:34:56")
            self.assertEqual(plc["classification"], "Physical endpoint")
            self.assertIn("corroborated by documented record", plc["classification_evidence"])
            self.assertEqual(plc["model"], "6ES7 315-2EH14-0AB0")
            # merge two NICs of one laptop; traffic from the alias lands on the primary
            a1 = store.add_documented_asset({"name": "ews-01", "mac": "ac:91:a1:00:00:01", "source": "Physical walkdown"})
            a2 = store.add_documented_asset({"name": "ews-01 wifi", "mac": "98:59:7a:00:00:02", "source": "Physical walkdown", "location": "Control room"})
            merged = store.merge_assets(a1["id"], a2["id"])
            self.assertEqual(merged["aliases"], ["98:59:7a:00:00:02"])
            self.assertEqual(merged["location"], "Control room")
            with self.assertRaises(ValueError):
                store.merge_assets(a1["id"], a1["id"])
            payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("98597a000002") + socket.inet_aton("192.168.4.61") + b"\x00" * 6 + socket.inet_aton("192.168.4.1")
            store.record(session, parse_ethernet(ethernet("ff:ff:ff:ff:ff:ff", "98:59:7a:00:00:02", 0x0806, payload), 1.0))
            primary = next(a for a in store.assets() if a["mac"] == "ac:91:a1:00:00:01")
            self.assertEqual(primary["ips"], "192.168.4.61")
            self.assertFalse(any(a["mac"] == "98:59:7a:00:00:02" for a in store.assets()))
            # delete guard
            with self.assertRaises(ValueError):
                store.delete_asset(plc["id"])
            rtu = next(a for a in store.assets() if a["name"] == "RTU-7 Lift station 7")
            store.delete_asset(rtu["id"])
            # report: lifecycle table and EOL/backup findings
            store.add_documented_asset({"name": "HMI-2", "mac": "00:aa:bb:cc:dd:10", "source": "Interview", "backup_status": "No backup", "criticality": "High"})
            an = Analysis(collect(store), False)
            self.assertTrue(any("End-of-life" in f["title"] for f in an.findings))
            self.assertTrue(any("backups" in f["title"] for f in an.findings))
            doc = zipfile.ZipFile(io.BytesIO(build_report(collect(store), {}))).read("word/document.xml").decode()
            self.assertIn("Lifecycle observations", doc)
            self.assertIn("6ES7 315-2EH14-0AB0", doc)
            self.assertIn("documented only", doc)


class FrameworkReferenceTests(unittest.TestCase):
    def test_every_draft_title_has_a_mapping_and_ids_resolve(self):
        import inspect
        import re
        from ot_scout import frameworks, report as rpt
        titles = set(re.findall(r'"title": "([^"]+)"', inspect.getsource(rpt.Analysis._findings)))
        self.assertTrue(titles)
        for title in titles:
            self.assertIn(title, frameworks.DRAFT_MAPPING, f"no framework mapping for draft: {title}")
        for iec, attack in frameworks.DRAFT_MAPPING.values():
            for ref in iec:
                self.assertIn(ref, frameworks.IEC62443, ref)
            for ref in attack:
                self.assertIn(ref, frameworks.ATTACK_ICS, ref)
        self.assertEqual(frameworks.describe("SR 5.1"), "SR 5.1 Network segmentation")
        self.assertEqual(frameworks.describe("SR 99.9"), "SR 99.9")
        refs = frameworks.refs_for("Direct OT-to-enterprise communications bypass the industrial DMZ")
        self.assertIn("SR 5.2 Zone boundary protection", refs["iec62443"])
        self.assertIn("T0886 Remote Services", refs["attack"])

    def test_references_survive_register_import_and_reach_the_report(self):
        import io
        import zipfile
        from ot_scout.report import Analysis, build_report, collect
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(str(Path(tmp) / "t.db"))
            store.save_finding({"title": "Manual", "kind": "Control deficiency", "iec62443": "SR 5.1 Network segmentation", "attack": "T0886 Remote Services"})
            f = store.findings()[0]
            self.assertEqual(f["iec62443"], "SR 5.1 Network segmentation")
            self.assertEqual(f["attack"], "T0886 Remote Services")
            # migration: an old database without the columns gains them on open
            import sqlite3
            old = str(Path(tmp) / "old.db")
            Store(old)
            with sqlite3.connect(old) as db:
                db.execute("CREATE TABLE findings_backup AS SELECT * FROM findings")
                db.execute("DROP TABLE findings")
                db.execute("""CREATE TABLE findings (id INTEGER PRIMARY KEY, ref TEXT NOT NULL DEFAULT '', title TEXT NOT NULL,
                    kind TEXT NOT NULL DEFAULT 'Evidence gap', rating TEXT NOT NULL DEFAULT 'Moderate', confidence TEXT NOT NULL DEFAULT 'Moderate',
                    owner TEXT NOT NULL DEFAULT '', condition TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '', impact TEXT NOT NULL DEFAULT '',
                    recommendation TEXT NOT NULL DEFAULT '', closure TEXT NOT NULL DEFAULT '', horizon TEXT NOT NULL DEFAULT '30-90 days',
                    status TEXT NOT NULL DEFAULT 'Draft', site TEXT NOT NULL DEFAULT '', assets TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'Assessor',
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
            reopened = Store(old)
            reopened.save_finding({"title": "After migration", "iec62443": "SR 7.8 Control system component inventory"})
            self.assertEqual(reopened.findings()[0]["iec62443"], "SR 7.8 Control system component inventory")
            # drafts carry references and the docx prints them
            drafts = Analysis(collect(store), False).drafts
            self.assertTrue(any(d.get("iec62443") for d in drafts))
            store.import_draft_findings(drafts)
            imported = [f for f in store.findings() if f["source"] == "OT Scout draft"]
            self.assertTrue(any(f["iec62443"] for f in imported))
            doc = zipfile.ZipFile(io.BytesIO(build_report(collect(store), {}))).read("word/document.xml").decode()
            self.assertIn("Framework references", doc)
            self.assertIn("SR 5.1 Network segmentation", doc)


def _ua_string(s):
    if s is None:
        return struct.pack("<i", -1)
    raw = s.encode()
    return struct.pack("<i", len(raw)) + raw


def _ua_bytes(b):
    return struct.pack("<i", -1) if b is None else struct.pack("<i", len(b)) + b


def _ua_localized(text):
    return b"\x02" + _ua_string(text)


def _ua_nodeid4(ident):
    return b"\x01\x00" + struct.pack("<H", ident)


def _ua_app(uri, product, name, app_type):
    return _ua_string(uri) + _ua_string(product) + _ua_localized(name) + struct.pack("<I", app_type) + _ua_string(None) + _ua_string(None) + struct.pack("<i", 0)


def _ua_request_header():
    return b"\x00\x00" + struct.pack("<qIII", 0, 1, 0, 0)[:0] + struct.pack("<q", 0) + struct.pack("<I", 1) + struct.pack("<I", 0) + _ua_string(None) + struct.pack("<I", 10000) + b"\x00\x00\x00"


def _ua_response_header():
    return struct.pack("<q", 0) + struct.pack("<I", 1) + struct.pack("<I", 0) + b"\x00" + struct.pack("<i", 0) + b"\x00\x00\x00"


def _ua_message(kind, body, is_final=b"F"):
    return kind + is_final + struct.pack("<I", 8 + len(body)) + body


def _ua_msg(type_id, body):
    return _ua_message(b"MSG", struct.pack("<IIII", 7, 1, 1, 1) + _ua_nodeid4(type_id) + body)


def _tcp_frame(src_ip, dst_ip, sport, dport, payload, src_mac="00:1c:06:11:22:33", dst_mac="00:aa:bb:cc:dd:ee"):
    return ethernet(dst_mac, src_mac, 0x0800, _ipv4(src_ip, dst_ip, 6, _tcp(sport, dport, payload)))


class OpcUaDecoderTests(unittest.TestCase):
    def test_hello_names_the_server_for_the_receiver(self):
        body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + _ua_string("opc.tcp://plc-line3.plant.local:4840/UA")
        obs = parse_ethernet(_tcp_frame("10.2.1.50", "10.2.1.10", 49000, 4840, _ua_message(b"HEL", body)), 1.0)
        self.assertEqual(obs.app_protocol, "OPC-UA")
        self.assertEqual(dict((f[0], f[1]) for f in obs.fingerprints)["role"], "OPC UA client")
        dst = dict((f[0], f[1]) for f in obs.dst_fingerprints)
        self.assertEqual(dst["role"], "OPC UA server")
        self.assertEqual(dst["opcua_endpoint"], "opc.tcp://plc-line3.plant.local:4840/UA")
        self.assertEqual(obs.dst_name_claims, [("plc-line3.plant.local", "OPC UA endpoint URL")])

    def test_opcua_is_recognised_on_a_non_standard_port(self):
        body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + _ua_string("opc.tcp://10.2.1.10:48010")
        obs = parse_ethernet(_tcp_frame("10.2.1.50", "10.2.1.10", 49000, 48010, _ua_message(b"HEL", body)), 1.0)
        self.assertEqual(obs.app_protocol, "OPC-UA")
        self.assertEqual(obs.dst_name_claims, [])  # host is an address, not a name

    def test_open_secure_channel_reports_policy_and_certificate_cn(self):
        cn = b"\x06\x03\x55\x04\x03\x0c\x0fKEPServerEX/UA"[:0]  # placeholder, built below
        der = b"\x30\x10" + b"\x06\x03\x55\x04\x03" + b"\x0c\x0e" + b"KEPServerEX/UA"
        body = struct.pack("<I", 0) + _ua_string("http://opcfoundation.org/UA/SecurityPolicy#None") + _ua_bytes(der) + _ua_bytes(None)
        body += struct.pack("<II", 1, 1) + _ua_nodeid4(446)
        obs = parse_ethernet(_tcp_frame("10.2.1.50", "10.2.1.10", 49000, 4840, _ua_message(b"OPN", body)), 1.0)
        fp = dict((f[0], f[1]) for f in obs.fingerprints)
        self.assertEqual(fp["opcua_security_policy"], "None")
        self.assertEqual(fp["opcua_certificate_cn"], "KEPServerEX/UA")
        self.assertEqual(fp["role"], "OPC UA client")

    def test_create_session_request_describes_client_and_server(self):
        body = _ua_request_header() + _ua_app("urn:scada01:Kepware.KEPServerEX.V6", "urn:kepware.com:KEPServerEX", "KEPServerEX/UA Client", 1)
        body += _ua_string("urn:plc-line3:Siemens:S7-1500") + _ua_string("opc.tcp://plc-line3:4840") + _ua_string("KEP session 1")
        body += _ua_bytes(b"\x00" * 32) + _ua_bytes(None) + struct.pack("<d", 60000.0) + struct.pack("<I", 0)
        obs = parse_ethernet(_tcp_frame("10.2.1.50", "10.2.1.10", 49000, 4840, _ua_msg(461, body)), 1.0)
        fp = dict((f[0], f[1]) for f in obs.fingerprints)
        self.assertEqual(fp["role"], "OPC UA client")
        self.assertEqual(fp["opcua_application"], "KEPServerEX/UA Client")
        self.assertEqual(fp["software"], "PTC Kepware")
        self.assertNotIn("manufacturer", fp)  # software vendor, not the box's maker
        dst = dict((f[0], f[1]) for f in obs.dst_fingerprints)
        self.assertEqual(dst["opcua_endpoint"], "opc.tcp://plc-line3:4840")
        self.assertEqual(dst["opcua_application_uri"], "urn:plc-line3:Siemens:S7-1500")

    def test_get_endpoints_response_describes_server_security_and_vendor(self):
        server = _ua_app("urn:plc-line3:Siemens:S7-1500", "http://siemens.com/simatic-s7-opcua", "SIMATIC.S7-1500.OPC-UA.Application:PLC_1", 0)
        def endpoint(mode, policy, tokens):
            e = _ua_string("opc.tcp://plc-line3:4840") + server + _ua_bytes(None) + struct.pack("<I", mode) + _ua_string(policy)
            e += struct.pack("<i", len(tokens))
            for t in tokens:
                e += _ua_string("p") + struct.pack("<I", t) + _ua_string(None) + _ua_string(None) + _ua_string(None)
            return e + _ua_string("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary") + b"\x00"
        body = _ua_response_header() + struct.pack("<i", 2) + endpoint(1, "http://opcfoundation.org/UA/SecurityPolicy#None", [0, 1]) + endpoint(3, "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256", [1])
        obs = parse_ethernet(_tcp_frame("10.2.1.10", "10.2.1.50", 4840, 49000, _ua_msg(431, body)), 1.0)
        fp = dict((f[0], f[1]) for f in obs.fingerprints)
        self.assertEqual(fp["role"], "OPC UA server")
        self.assertEqual(fp["manufacturer"], "Siemens")
        self.assertEqual(fp["opcua_security_modes"], "None, SignAndEncrypt")
        self.assertEqual(fp["opcua_security_policies"], "Basic256Sha256, None")
        self.assertEqual(fp["opcua_user_tokens"], "Anonymous, User name")

    def test_activate_session_reports_anonymous_and_username_auth(self):
        prefix = _ua_request_header() + _ua_string(None) + _ua_bytes(None) + struct.pack("<i", 0) + struct.pack("<i", 0)
        anon = prefix + _ua_nodeid4(321) + b"\x01" + _ua_bytes(_ua_string("anon")) + _ua_string(None) + _ua_bytes(None)
        fp = dict((f[0], f[1]) for f in parse_ethernet(_tcp_frame("10.2.1.50", "10.2.1.10", 49000, 4840, _ua_msg(467, anon)), 1.0).fingerprints)
        self.assertEqual(fp["opcua_auth"], "Anonymous")
        token = _ua_string("username") + _ua_string("operator") + _ua_bytes(b"secret") + _ua_string(None)
        user = prefix + _ua_nodeid4(324) + b"\x01" + _ua_bytes(token) + _ua_string(None) + _ua_bytes(None)
        fp = dict((f[0], f[1]) for f in parse_ethernet(_tcp_frame("10.2.1.50", "10.2.1.10", 49000, 4840, _ua_msg(467, user)), 1.0).fingerprints)
        self.assertEqual(fp["opcua_auth"], "User name (operator)")
        self.assertFalse(any("secret" in f[1] for f in parse_ethernet(_tcp_frame("10.2.1.50", "10.2.1.10", 49000, 4840, _ua_msg(467, user)), 1.0).fingerprints))

    def test_encrypted_body_yields_nothing_but_no_crash(self):
        import os
        body = struct.pack("<IIII", 7, 1, 1, 1) + os.urandom(200)
        obs = parse_ethernet(_tcp_frame("10.2.1.50", "10.2.1.10", 49000, 4840, _ua_message(b"MSG", body)), 1.0)
        self.assertEqual(obs.app_protocol, "OPC-UA")
        self.assertEqual(obs.fingerprints, [])

    def test_store_attributes_receiver_claims_to_the_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(str(Path(tmp) / "t.db"))
            sid = store.begin_session("a", "s", "p", "eth0", "live", "Configured SPAN/mirror")
            body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + _ua_string("opc.tcp://plc-line3.plant.local:4840")
            store.record(sid, parse_ethernet(_tcp_frame("10.2.1.50", "10.2.1.10", 49000, 4840, _ua_message(b"HEL", body)), 1.0))
            server = next(a for a in store.assets() if a["mac"] == "00:aa:bb:cc:dd:ee")
            self.assertEqual(server["name"], "plc-line3.plant.local")
            self.assertEqual(server["display_type"], "OPC UA server")


def _enip(command, context, cpf_items, session=1):
    body = struct.pack("<IH", 0, 0) + struct.pack("<H", len(cpf_items)) + b"".join(struct.pack("<HH", t, len(d)) + d for t, d in cpf_items)
    return struct.pack("<HHII", command, len(body), session, 0) + context + struct.pack("<I", 0) + body


class EnipExplicitTests(unittest.TestCase):
    def test_get_attributes_all_on_identity_is_paired_with_its_request(self):
        ctx = b"OTSCOUT1"
        request = bytes([0x01, 0x02, 0x20, 0x01, 0x24, 0x01])  # Get_Attributes_All, class 1 instance 1
        req_frame = _tcp_frame("10.3.0.5", "10.3.0.20", 51000, 44818, _enip(0x6F, ctx, [(0, b""), (0xB2, request)]), "00:aa:00:00:00:01", "00:aa:00:00:00:02")
        fp = dict((f[0], f[1]) for f in parse_ethernet(req_frame, 1.0).fingerprints)
        self.assertEqual(fp["role"], "EtherNet/IP client (HMI/engineering)")
        name = b"1756-L83E/B"
        identity = struct.pack("<HHHBBHI", 1, 0x0E, 166, 32, 11, 0x0060, 0x00C0FFEE) + bytes([len(name)]) + name + b"\x03"
        response = bytes([0x81, 0x00, 0x00, 0x00]) + identity
        rsp_frame = _tcp_frame("10.3.0.20", "10.3.0.5", 44818, 51000, _enip(0x6F, ctx, [(0, b""), (0xB2, response)]), "00:aa:00:00:00:02", "00:aa:00:00:00:01")
        obs = parse_ethernet(rsp_frame, 1.0)
        fp = dict((f[0], f[1]) for f in obs.fingerprints)
        self.assertEqual(fp["manufacturer"], "Rockwell Automation / Allen-Bradley")
        self.assertEqual(fp["role"], "PLC (EtherNet/IP)")
        self.assertEqual(fp["model"], "1756-L83E/B")
        self.assertEqual(fp["firmware"], "32.011")
        self.assertEqual(fp["serial"], "00C0FFEE")
        self.assertEqual(fp["cip_device_type"], "Programmable Logic Controller")
        # a second, unpaired response is ignored
        self.assertEqual(parse_ethernet(rsp_frame, 1.0).fingerprints, [])

    def test_unconnected_send_wrapper_and_single_attribute(self):
        ctx = b"OTSCOUT2"
        embedded = bytes([0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x07])  # Get_Attribute_Single identity attr 7 (product name)
        ucs = bytes([0x52, 0x02, 0x20, 0x06, 0x24, 0x01, 0x0A, 0x05]) + struct.pack("<H", len(embedded)) + embedded + bytes([0x01, 0x00, 0x01, 0x00])
        req = _tcp_frame("10.3.0.5", "10.3.0.20", 51001, 44818, _enip(0x6F, ctx, [(0, b""), (0xB2, ucs)]), "00:aa:00:00:00:01", "00:aa:00:00:00:02")
        parse_ethernet(req, 1.0)
        name = b"PowerFlex 755"
        rsp = _tcp_frame("10.3.0.20", "10.3.0.5", 44818, 51001, _enip(0x6F, ctx, [(0, b""), (0xB2, bytes([0x8E, 0, 0, 0, len(name)]) + name)]), "00:aa:00:00:00:02", "00:aa:00:00:00:01")
        fp = dict((f[0], f[1]) for f in parse_ethernet(rsp, 1.0).fingerprints)
        self.assertEqual(fp["model"], "PowerFlex 755")

    def test_list_identity_uses_the_same_vendor_and_type_tables(self):
        name = b"1734-AENT/B"
        item = b"\x01\x00" + b"\x00" * 16 + struct.pack("<HHHBBHI", 1, 0x0C, 34, 5, 16, 0x0030, 0x11223344) + bytes([len(name)]) + name + b"\x03"
        payload = struct.pack("<HHII", 0x63, 4 + len(item) + 2, 0, 0) + b"\x00" * 8 + struct.pack("<I", 0) + struct.pack("<H", 1) + struct.pack("<HH", 0x0C, len(item)) + item
        frame = ethernet("ff:ff:ff:ff:ff:ff", "00:aa:00:00:00:03", 0x0800, _ipv4("10.3.0.30", "10.3.0.255", 17, struct.pack("!HHHH", 44818, 44818, 8 + len(payload), 0) + payload))
        fp = dict((f[0], f[1]) for f in parse_ethernet(frame, 1.0).fingerprints)
        self.assertEqual(fp["manufacturer"], "Rockwell Automation / Allen-Bradley")
        self.assertEqual(fp["role"], "Communications adapter")
        self.assertEqual(fp["firmware"], "5.016")
        self.assertEqual(fp["model"], "1734-AENT/B")


class EvidenceTests(unittest.TestCase):
    def test_pcap_writer_round_trips_through_the_importer(self):
        from ot_scout.capture import PcapWriter, iter_pcap
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "captures" / "s.pcap"
            w = PcapWriter(path)
            frames = [_tcp_frame("10.0.0.1", "10.0.0.2", 1000 + i, 502, b"\x00" * i) for i in range(5)]
            for i, f in enumerate(frames):
                w.write(f, 1_700_000_000.25 + i)
            w.close()
            back = list(iter_pcap(path.read_bytes()))
            self.assertEqual([f for _, f in back], frames)
            self.assertAlmostEqual(back[0][0], 1_700_000_000.25, places=3)

    def test_session_records_frames_drops_and_pcap_path_and_migrates_old_databases(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(str(Path(tmp) / "t.db"))
            sid = store.begin_session("a", "s", "p", "eth0", "live", "Configured SPAN/mirror")
            store.set_session_pcap(sid, "/x/session-001.pcap")
            store.end_session(sid, dropped=42, frames=1000)
            sess = store.sessions()[0]
            self.assertEqual((sess["dropped"], sess["frames"], sess["pcap_path"]), (42, 1000, "/x/session-001.pcap"))
            old = str(Path(tmp) / "old.db"); Store(old)
            with sqlite3.connect(old) as db:
                db.execute("ALTER TABLE sessions DROP COLUMN dropped"); db.execute("ALTER TABLE sessions DROP COLUMN frames"); db.execute("ALTER TABLE sessions DROP COLUMN pcap_path")
            reopened = Store(old)
            sid = reopened.begin_session("a", "s", "p", "eth0", "live", "Configured SPAN/mirror")
            reopened.end_session(sid, dropped=1, frames=2)
            self.assertEqual(reopened.sessions()[0]["dropped"], 1)

    def test_record_many_matches_record_one_by_one(self):
        frames = [_tcp_frame(f"10.0.0.{1 + i % 3}", "10.0.0.9", 40000 + i, 502, b"") for i in range(30)]
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Store(str(Path(tmp) / "a.db")), Store(str(Path(tmp) / "b.db"))
            sa = a.begin_session("x", "s", "p", "eth0"); sb = b.begin_session("x", "s", "p", "eth0")
            for i, f in enumerate(frames):
                a.record(sa, parse_ethernet(f, 1.0 + i), "")
            b.record_many(sb, [parse_ethernet(f, 1.0 + i) for i, f in enumerate(frames)], "")
            strip = lambda rows: [{k: v for k, v in r.items() if k not in ("id", "first_seen", "last_seen")} for r in rows]
            self.assertEqual(strip(a.connections()), strip(b.connections()))
            self.assertEqual([x["mac"] for x in a.assets()], [x["mac"] for x in b.assets()])
            self.assertEqual(a.sessions()[0]["packets"], b.sessions()[0]["packets"])

    def test_evidence_package_manifest_hashes_verify(self):
        import hashlib, io, zipfile
        from ot_scout.capture import CaptureManager, PcapWriter
        from ot_scout.web import AppServer, Handler
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(str(Path(tmp) / "t.db"))
            sid = store.begin_session("a", "s", "Control room", "eth0", "live", "Configured SPAN/mirror")
            pcap = Path(tmp) / "captures" / "session-001.pcap"
            w = PcapWriter(pcap); w.write(_tcp_frame("10.0.0.1", "10.0.0.2", 1000, 502, b""), 1.0); w.close()
            store.set_session_pcap(sid, str(pcap)); store.end_session(sid, dropped=0, frames=1)
            server = AppServer.__new__(AppServer)
            server.store = store; server.capture = CaptureManager(store); server.main_database = store.path; server.demo_database = str(Path(tmp) / "demo.db")
            handler = Handler.__new__(Handler); handler.server = server
            path = Handler.build_evidence_package(handler, {})
            try:
                with zipfile.ZipFile(path) as zf:
                    names = set(zf.namelist())
                    self.assertTrue({"assessment.json", "report.docx", "assets.csv", "purdue-zones.svg", "MANIFEST.txt", "captures/session-001.pcap"} <= names)
                    manifest = zf.read("MANIFEST.txt").decode()
                    checked = 0
                    for line in zf.read("SHA256SUMS").decode().splitlines():
                        digest, name = line.split("  ", 1)
                        self.assertIn(name, names)
                        self.assertEqual(hashlib.sha256(zf.read(name)).hexdigest(), digest); checked += 1
                    self.assertGreaterEqual(checked, 8)
                    self.assertIn("frames=1 recorded=0 dropped=0", manifest)
            finally:
                Path(path).unlink()


class RealCaptureTests(unittest.TestCase):
    """Fixtures captured from real implementations, not built from the spec by hand."""

    def test_opcua_asyncua_capture(self):
        # opcua-asyncio 2.x server + client on loopback: Hello/OPN/CreateSession/ActivateSession (anonymous, then user name)
        from ot_scout.capture import iter_pcap
        data = (Path(__file__).parent / "fixtures" / "opcua-asyncua.pcap").read_bytes()
        obs = [o for o in (parse_ethernet(f, ts) for ts, f in iter_pcap(data)) if o]
        self.assertEqual(len(obs), 114)
        self.assertTrue(all(o.app_protocol == "OPC-UA" for o in obs))
        # loopback frames have a zero MAC (no asset in the store), so check the decoded claims directly
        fps = {(k, v) for o in obs for k, v, _, _ in o.fingerprints + o.dst_fingerprints}
        if True:
            for expected in [("opcua_application", "Riverbend Filter PLC OPC UA Server"), ("opcua_product", "urn:otscout-test:asyncua"),
                             ("opcua_endpoint", "opc.tcp://127.0.0.1:4840/riverbend/plc"), ("opcua_security_policies", "None"),
                             ("opcua_user_tokens", "Anonymous, Certificate, User name"), ("opcua_auth", "Anonymous"),
                             ("opcua_auth", "User name (operator)"), ("software", "FreeOpcUa (open source)"), ("role", "OPC UA server"), ("role", "OPC UA client")]:
                self.assertIn(expected, fps)
            self.assertFalse(any("wrong-password" in v for _, v in fps))


class ExposureTests(unittest.TestCase):
    def test_score_is_itemised_and_capped(self):
        from ot_scout.exposure import score_asset, band
        asset = {"id": 1, "physical_asset": 1, "criticality": "Critical", "support_status": "End of support", "backup_status": "No backup", "purdue_level": "Level 1",
                 "fingerprints": [{"field": "opcua_security_policies", "value": "None"}]}
        rels = [{"key_a": "asset:1", "key_b": "ip:8.8.8.8", "level_a": "Level 1", "level_b": "External", "crossing": "OT to external/internet", "decision": "Unexpected"},
                {"key_a": "asset:1", "key_b": "asset:2", "level_a": "Level 1", "level_b": "Level 4", "crossing": "OT to enterprise (bypasses industrial DMZ)", "decision": "Unknown"}]
        r = score_asset(asset, rels, {23, 161})
        self.assertEqual(r["exposure"], 100)  # 40+25+15+15+10+8+10 = 123, capped
        self.assertEqual(r["exposure_band"], "Critical")
        self.assertTrue(any(f.startswith("Talks to an external endpoint") and "(+25)" in f for f in r["exposure_factors"]))
        self.assertTrue(any("Telnet" in f and "SNMP" in f for f in r["exposure_factors"]))
        named = score_asset({"id": 3, "name": "CAM-01", "mac": "d0:3f:27:70:00:01", "physical_asset": 1, "criticality": "Low", "purdue_level": "Level 1", "support_status": "Supported", "backup_status": "Backed up and tested"}, [], set(),
                            [{"ref": "FND-01", "rating": "Critical", "status": "Validated", "assets": "d0:3f:27:70:00:01 on PROC-SW2"}, {"ref": "FND-09", "rating": "Moderate", "status": "Rejected", "assets": "CAM-01"}])
        self.assertEqual(named["exposure"], 30)  # 10 + 20; the rejected finding does not count
        self.assertTrue(any("FND-01" in f for f in named["exposure_factors"]))
        quiet = score_asset({"id": 2, "physical_asset": 1, "criticality": "Low", "purdue_level": "Level 2", "support_status": "Supported", "backup_status": "Backed up and tested"}, [], set())
        self.assertEqual((quiet["exposure"], quiet["exposure_band"]), (10, "Low"))
        self.assertEqual(band(69), "High"); self.assertEqual(band(70), "Critical")

    def test_store_annotates_assets_and_report_prints_the_sections(self):
        import io, zipfile
        from ot_scout.report import build_report, collect
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(str(Path(tmp) / "t.db"))
            sid = store.begin_session("a", "s", "p", "eth0", "live", "Configured SPAN/mirror")
            frames = [_tcp_frame("10.0.0.1", "10.0.0.2", 40000 + i, 23, b"", "00:1c:06:00:00:01", "00:1c:06:00:00:02") for i in range(3)]
            frames += [_tcp_frame("10.0.0.2", "10.0.0.1", 23, 40000 + i, b"", "00:1c:06:00:00:02", "00:1c:06:00:00:01") for i in range(3)]
            store.record_many(sid, [parse_ethernet(f, 1.0 + i) for i, f in enumerate(frames)])
            assets = store.assets_with_exposure()
            self.assertTrue(all("exposure" in a for a in assets))
            server = next(a for a in assets if a["mac"] == "00:1c:06:00:00:02")
            self.assertTrue(any("Telnet" in f for f in server["exposure_factors"]))
            store.save_finding({"title": "Telnet on a switch", "kind": "Control deficiency", "rating": "Moderate", "status": "Validated", "iec62443": "SR 4.1 Information confidentiality; SR 1.13 Access via untrusted networks"})
            doc = zipfile.ZipFile(io.BytesIO(build_report(collect(store), {}))).read("word/document.xml").decode()
            for text in ("Assets to address first", "Fleet view by manufacturer and model", "IEC 62443 requirements addressed by the findings", "SR 4.1"):
                self.assertIn(text, doc)
