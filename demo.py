#!/usr/bin/env python3
"""Build a demonstration database for OT Scout using entirely fictitious data.

Creates data/demo.db describing "Riverbend Regional Water Utility" (an invented client):
a control-room SPAN capture, a lift-station access-port capture, decoded industrial
fingerprints, a walkdown spreadsheet of silent assets, a filled site checklist, network
legs, Purdue placement, conduit decisions and a validated findings register.

Run:   python3 demo.py                  (writes data/demo.db and demo-report.docx)
Then:  sudo python3 run.py --database data/demo.db

Nothing here is real. MAC addresses, IPs, names and findings are invented for the mockup.
"""
from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from ot_scout.parser import parse_ethernet  # noqa: E402
from ot_scout.frameworks import format_refs  # noqa: E402
from ot_scout.report import build_report, collect  # noqa: E402
from ot_scout.store import Store  # noqa: E402

DB = Path(__file__).parent / "data" / "demo.db"
COLLECTOR = "00:14:22:aa:00:01"  # the assessor laptop's NIC


def mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def eth(dst: str, src: str, ethertype: int, payload: bytes) -> bytes:
    return mac_bytes(dst) + mac_bytes(src) + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    hdr = bytearray(20)
    hdr[0] = 0x45; hdr[8] = 64; hdr[9] = proto
    hdr[2:4] = struct.pack("!H", 20 + len(payload))
    hdr[12:16] = socket.inet_aton(src); hdr[16:20] = socket.inet_aton(dst)
    return bytes(hdr) + payload


def ua_string(text):
    if text is None:
        return struct.pack("<i", -1)
    raw = text.encode()
    return struct.pack("<i", len(raw)) + raw


def ua_bytes(raw):
    return struct.pack("<i", -1) if raw is None else struct.pack("<i", len(raw)) + raw


def ua_app(uri, product, name, app_type):
    return ua_string(uri) + ua_string(product) + b"\x02" + ua_string(name) + struct.pack("<I", app_type) + ua_string(None) + ua_string(None) + struct.pack("<i", 0)


def tcp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIHHHH", sport, dport, 1, 1, 0x5018, 8192, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def arp(src_mac: str, src_ip: str, target_ip: str) -> bytes:
    payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac_bytes(src_mac) + socket.inet_aton(src_ip) + b"\x00" * 6 + socket.inet_aton(target_ip)
    return eth("ff:ff:ff:ff:ff:ff", src_mac, 0x0806, payload)


# ----------------------------------------------------------------------------- devices
DEVICES = {
    # key: (mac, ip, vendor)
    "scada1":   ("00:14:22:10:00:11", "10.20.3.11", "Dell Inc."),
    "scada2":   ("00:14:22:10:00:12", "10.20.3.12", "Dell Inc."),
    "hist":     ("00:14:22:10:00:21", "10.20.3.21", "Dell Inc."),
    "ews":      ("3c:d9:2b:20:00:31", "10.20.2.31", "Hewlett Packard"),
    "hmi1":     ("00:0e:8c:20:00:41", "10.20.2.41", "Siemens AG"),
    "hmi2":     ("00:0e:8c:20:00:42", "10.20.2.42", "Siemens AG"),
    "plc_ftr":  ("00:1c:06:30:00:51", "10.20.1.51", "Siemens AG"),
    "plc_chem": ("00:1c:06:30:00:52", "10.20.1.52", "Siemens AG"),
    "plc_hsp":  ("00:00:bc:30:00:61", "10.20.1.61", "Rockwell Automation"),
    "rtu_ls7":  ("00:30:a7:40:00:71", "10.20.7.71", "Schweitzer Engineering Laboratories"),
    "rtu_ls9":  ("00:30:a7:40:00:72", "10.20.7.72", "Schweitzer Engineering Laboratories"),
    "moxa":     ("00:90:e8:30:00:81", "10.20.1.81", "Moxa Technologies"),
    "sw_ctrl":  ("00:1a:a1:50:00:01", "10.20.0.2", "Cisco Systems"),
    "sw_proc":  ("00:1a:a1:50:00:02", "10.20.0.3", "Cisco Systems"),
    "fw":       ("00:1a:a1:50:00:09", "10.20.0.1", "Cisco Systems"),
    "dc":       ("00:14:22:60:00:91", "10.50.1.10", "Dell Inc."),
    "ad_ws":    ("00:14:22:60:00:92", "10.50.4.55", "Dell Inc."),
    "cam":      ("d0:3f:27:70:00:01", "10.20.9.101", "Wyze Labs Inc"),
}
VENDOR_PREFIX = {v[0].replace(":", "")[:6].upper(): v[2] for v in DEVICES.values()}
VENDOR_PREFIX["001422"] = "Dell Inc."


class Demo:
    def __init__(self, path: Path = DB):
        path = Path(path)
        if path.exists():
            path.unlink()
        for suffix in ("-wal", "-shm"):
            p = Path(str(path) + suffix)
            if p.exists():
                p.unlink()
        self.store = Store(path)
        self.store.vendors.prefixes.update(VENDOR_PREFIX)
        self.t = time.time() - 4 * 3600

    def rec(self, session, frame, count=1, local=COLLECTOR):
        for _ in range(count):
            self.t += 0.37
            obs = parse_ethernet(frame, self.t)
            if obs:
                self.store.record(session, obs, local)

    def flow(self, session, a, b, sport, dport, n=20, proto="tcp", reply=True, payload=b""):
        ma, ia, _ = DEVICES[a] if a in DEVICES else a
        mb, ib, _ = DEVICES[b] if b in DEVICES else b
        seg = (tcp if proto == "tcp" else udp)
        self.rec(session, eth(mb, ma, 0x0800, ipv4(ia, ib, 6 if proto == "tcp" else 17, seg(sport, dport, payload))), n)
        if reply:
            self.rec(session, eth(ma, mb, 0x0800, ipv4(ib, ia, 6 if proto == "tcp" else 17, seg(dport, sport))), n)

    # ---- fingerprint payloads
    @staticmethod
    def opcua_hello(url):
        body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + ua_string(url)
        return b"HELF" + struct.pack("<I", 8 + len(body)) + body

    @staticmethod
    def opcua_msg(type_id, body):
        body = struct.pack("<IIII", 7, 1, 1, 1) + b"\x01\x00" + struct.pack("<H", type_id) + body
        return b"MSGF" + struct.pack("<I", 8 + len(body)) + body

    @classmethod
    def opcua_create_session_request(cls, app_uri, product_uri, app_name, server_uri, endpoint):
        req_header = b"\x00\x00" + struct.pack("<qII", 0, 1, 0) + ua_string(None) + struct.pack("<I", 10000) + b"\x00\x00\x00"
        body = req_header + ua_app(app_uri, product_uri, app_name, 1) + ua_string(server_uri) + ua_string(endpoint) + ua_string("Historian collector")
        body += ua_bytes(b"\x00" * 32) + ua_bytes(None) + struct.pack("<d", 60000.0) + struct.pack("<I", 0)
        return cls.opcua_msg(461, body)

    @classmethod
    def opcua_get_endpoints_response(cls, endpoint, app_uri, product_uri, app_name, endpoints):
        rsp_header = struct.pack("<qII", 0, 1, 0) + b"\x00" + struct.pack("<i", 0) + b"\x00\x00\x00"
        server = ua_app(app_uri, product_uri, app_name, 0)
        body = rsp_header + struct.pack("<i", len(endpoints))
        for mode, policy, tokens in endpoints:
            body += ua_string(endpoint) + server + ua_bytes(None) + struct.pack("<I", mode) + ua_string(policy) + struct.pack("<i", len(tokens))
            for t in tokens:
                body += ua_string("policy") + struct.pack("<I", t) + ua_string(None) + ua_string(None) + ua_string(None)
            body += ua_string("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary") + b"\x00"
        return cls.opcua_msg(431, body)

    @staticmethod
    def opcua_open_channel(policy_uri, cn):
        der = b"\x30\x10" + b"\x06\x03\x55\x04\x03" + bytes([0x0C, len(cn)]) + cn.encode()
        body = struct.pack("<I", 0) + ua_string(policy_uri) + ua_bytes(der) + ua_bytes(None) + struct.pack("<II", 1, 1) + b"\x01\x00" + struct.pack("<H", 446)
        return b"OPNF" + struct.pack("<I", 8 + len(body)) + body

    @classmethod
    def opcua_activate_anonymous(cls):
        req_header = b"\x00\x00" + struct.pack("<qII", 0, 2, 0) + ua_string(None) + struct.pack("<I", 10000) + b"\x00\x00\x00"
        body = req_header + ua_string(None) + ua_bytes(None) + struct.pack("<i", 0) + struct.pack("<i", 0)
        body += b"\x01\x00" + struct.pack("<H", 321) + b"\x01" + ua_bytes(ua_string("anonymous")) + ua_string(None) + ua_bytes(None)
        return cls.opcua_msg(467, body)

    @staticmethod
    def enip_rr(context, cip):
        body = struct.pack("<IH", 0, 0) + struct.pack("<H", 2) + struct.pack("<HH", 0, 0) + struct.pack("<HH", 0xB2, len(cip)) + cip
        return struct.pack("<HHII", 0x6F, len(body), 1, 0) + context + struct.pack("<I", 0) + body

    @classmethod
    def enip_identity_exchange(cls, context, vendor, device_type, product_code, major, minor, serial, name):
        request = bytes([0x01, 0x02, 0x20, 0x01, 0x24, 0x01])
        raw = name.encode()
        identity = struct.pack("<HHHBBHI", vendor, device_type, product_code, major, minor, 0x0060, serial) + bytes([len(raw)]) + raw + b"\x03"
        return cls.enip_rr(context, request), cls.enip_rr(context, bytes([0x81, 0, 0, 0]) + identity)

    @staticmethod
    def s7_szl_response():
        def entry(index, mlfb, bgtyp, ausbg, ausbe):
            return struct.pack("!H", index) + mlfb.ljust(20).encode() + struct.pack("!HHH", bgtyp, ausbg, ausbe)
        entries = entry(1, "6ES7 315-2EH14-0AB0", 0x2001, 0x0003, 0x0001) + entry(7, "6ES7 315-2EH14-0AB0", 0x2001, 0x5603, 0x0207)
        szl = bytes([0xFF, 0x09]) + struct.pack("!H", 8 + len(entries)) + struct.pack("!HHHH", 0x0011, 0x0000, 28, 2) + entries
        params = bytes([0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00])
        s7 = bytes([0x32, 0x07, 0x00, 0x00, 0x00, 0x01]) + struct.pack("!HH", len(params), len(szl)) + params + szl
        cotp = bytes([0x02, 0xF0, 0x80])
        return bytes([3, 0]) + struct.pack("!H", 4 + len(cotp) + len(s7)) + cotp + s7

    @staticmethod
    def s7_szl_001c(plc_name, serial, module_type):
        def entry(index, value):
            return struct.pack("!H", index) + value.ljust(32, "\x00").encode()[:32]
        entries = entry(1, plc_name) + entry(5, serial) + entry(7, module_type)
        szl = bytes([0xFF, 0x09]) + struct.pack("!H", 8 + len(entries)) + struct.pack("!HHHH", 0x001C, 0x0000, 34, 3) + entries
        params = bytes([0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00])
        s7 = bytes([0x32, 0x07, 0x00, 0x00, 0x00, 0x02]) + struct.pack("!HH", len(params), len(szl)) + params + szl
        cotp = bytes([0x02, 0xF0, 0x80])
        return bytes([3, 0]) + struct.pack("!H", 4 + len(cotp) + len(s7)) + cotp + s7

    @staticmethod
    def enip_list_identity(product, serial):
        name = product.encode()
        item = struct.pack("<HHH", 0x0001, 0x000C, 0) + struct.pack("<HHH", 1, 0x0C, 0)  # placeholder, rebuilt below
        body = struct.pack("<H", 1)  # encapsulation version
        body += struct.pack("!HH", 2, 44818) + socket.inet_aton("10.20.1.61") + b"\x00" * 8  # sockaddr
        body += struct.pack("<HHH", 0x0001, 0x000E, 0x0058)  # vendor (Rockwell), device type (PLC), product code
        body += bytes([20, 11]) + struct.pack("<H", 0x0030) + struct.pack("<I", serial) + bytes([len(name)]) + name + b"\x03"
        item = struct.pack("<HH", 0x000C, len(body)) + body
        header = struct.pack("<HHIIQI", 0x0063, len(item) + 2, 0, 0, 0, 0)
        return header + struct.pack("<H", 1) + item

    @staticmethod
    def dnp3_unsolicited(src_addr, dst_addr, iin1=0x90):
        from ot_scout.parser import _dnp3_crc
        header = bytes([0x05, 0x64, 0x0A, 0x44]) + struct.pack("<HH", dst_addr, src_addr)
        link = header + struct.pack("<H", _dnp3_crc(header))
        return link + bytes([0xC0, 0xC0, 0x82, iin1, 0x00]) + b"\x00\x00"

    @staticmethod
    def dnp3_read(src_addr, dst_addr):
        from ot_scout.parser import _dnp3_crc
        header = bytes([0x05, 0x64, 0x08, 0xC4]) + struct.pack("<HH", dst_addr, src_addr)
        link = header + struct.pack("<H", _dnp3_crc(header))
        return link + bytes([0xC0, 0xC0, 0x01]) + b"\x00\x00"

    @staticmethod
    def modbus_device_id():
        objects = [(0, b"Moxa Technologies"), (1, b"MGate MB3170"), (2, b"V2.3"), (4, b"MGate MB3170 Modbus gateway")]
        pdu = b"\x2b\x0e\x01\x00\x00\x00" + bytes([len(objects)]) + b"".join(bytes([i, len(v)]) + v for i, v in objects)
        return struct.pack("!HHHB", 1, 0, len(pdu) + 1, 1) + pdu

    @staticmethod
    def profinet_dcp(station, vendor_value, vendor_id, device_id, ip, mask, gw, role=0x01):
        def block(option, sub, body):
            data = struct.pack("!BBH", option, sub, len(body)) + body
            return data + (b"\x00" if len(body) & 1 else b"")
        blocks = (block(2, 1, b"\x00\x00" + vendor_value.encode()) + block(2, 2, b"\x00\x00" + station.encode()) +
                  block(2, 3, b"\x00\x00" + struct.pack("!HH", vendor_id, device_id)) + block(2, 4, b"\x00\x00" + bytes([role, 0])) +
                  block(1, 2, b"\x00\x01" + socket.inet_aton(ip) + socket.inet_aton(mask) + socket.inet_aton(gw)))
        return struct.pack("!HBBIHH", 0xFEFF, 0x05, 0x01, 0x1234, 0, len(blocks)) + blocks

    @staticmethod
    def lldp(system_name, description, port):
        def tlv(kind, value):
            return struct.pack("!H", (kind << 9) | len(value)) + value
        return tlv(1, b"\x04" + b"\x00" * 6) + tlv(2, b"\x05" + port.encode()) + tlv(3, b"\x00\x78") + tlv(5, system_name.encode()) + tlv(6, description.encode()) + tlv(4, port.encode()) + tlv(0, b"")

    @staticmethod
    def dhcp_request(mac, hostname, vendor_class):
        body = bytearray(240)
        body[0] = 1; body[1] = 1; body[2] = 6
        body[28:34] = mac_bytes(mac)
        body[236:240] = b"\x63\x82\x53\x63"
        opts = b"\x35\x01\x03" + b"\x0c" + bytes([len(hostname)]) + hostname.encode() + b"\x3c" + bytes([len(vendor_class)]) + vendor_class.encode() + b"\x37\x05\x01\x03\x06\x0f\x2a" + b"\xff"
        return bytes(body) + opts

    @staticmethod
    def http_response(server):
        return f"HTTP/1.1 200 OK\r\nServer: {server}\r\nContent-Type: text/html\r\n\r\n<html></html>".encode()

    @staticmethod
    def mdns_answer(name, ip):
        q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
        hdr = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        ans = q + struct.pack("!HHIH", 1, 0x8001, 120, 4) + socket.inet_aton(ip)
        return hdr + ans

    # ---- sessions
    def control_room_span(self):
        st = self.store
        s = st.begin_session("Riverbend Regional Water Utility — OT assessment", "Main WTP", "Control room core switch SPAN", "eth0", "live", "Configured SPAN/mirror")
        D = DEVICES
        # ARP from everyone so IPs are anchored
        for key, (mac, ip, _v) in D.items():
            if key in ("rtu_ls7", "rtu_ls9", "cam"):
                continue
            self.rec(s, arp(mac, ip, "10.20.0.1"), 3)
        # LLDP from switches / firewall
        self.rec(s, eth("01:80:c2:00:00:0e", D["sw_ctrl"][0], 0x88CC, self.lldp("WTP-CORE-SW1", "Cisco IE-4000 Industrial Ethernet Switch, IOS 15.2(7)E4", "Gi1/1")), 12)
        self.rec(s, eth("01:80:c2:00:00:0e", D["sw_proc"][0], 0x88CC, self.lldp("WTP-PROC-SW2", "Cisco IE-3400 Industrial Ethernet Switch, IOS-XE 17.6", "Gi1/2")), 12)
        self.rec(s, eth("01:80:c2:00:00:0e", D["fw"][0], 0x88CC, self.lldp("WTP-OTFW-1", "Cisco Firepower 1120, FTD 7.2", "Ethernet1/1")), 12)
        # DHCP hostnames for workstations / HMIs
        for key, host, cls in (("ews", "WTP-EWS01", "MSFT 5.0"), ("hmi1", "WTP-HMI-FILTERS", "MSFT 5.0"), ("hmi2", "WTP-HMI-CHEM", "MSFT 5.0"), ("scada1", "WTP-SCADA-A", "MSFT 5.0"), ("scada2", "WTP-SCADA-B", "MSFT 5.0"), ("hist", "WTP-HIST01", "MSFT 5.0")):
            mac, ip, _ = D[key]
            self.rec(s, eth("ff:ff:ff:ff:ff:ff", mac, 0x0800, ipv4(ip, "255.255.255.255", 17, udp(68, 67, self.dhcp_request(mac, host, cls)))), 2)
        # mDNS names for infrastructure
        self.rec(s, eth("01:00:5e:00:00:fb", D["dc"][0], 0x0800, ipv4(D["dc"][1], "224.0.0.251", 17, udp(5353, 5353, self.mdns_answer("RVB-DC01.local", D["dc"][1])))), 3)
        # S7: EWS and SCADA talk to Siemens PLCs; PLC answers SZL
        for plc in ("plc_ftr", "plc_chem"):
            self.flow(s, "scada1", plc, 49152, 102, n=180)
            self.flow(s, "scada2", plc, 49153, 102, n=40)
            self.flow(s, "ews", plc, 49200, 102, n=25)
            mac, ip, _ = D[plc]
            ews_mac, ews_ip, _ = D["ews"]
            self.rec(s, eth(ews_mac, mac, 0x0800, ipv4(ip, ews_ip, 6, tcp(102, 49200, self.s7_szl_response()))), 2)
            name = "FILTER-PLC-01" if plc == "plc_ftr" else "CHEM-PLC-02"
            self.rec(s, eth(ews_mac, mac, 0x0800, ipv4(ip, ews_ip, 6, tcp(102, 49200, self.s7_szl_001c(name, "S C-D4X" + ("11207" if plc == "plc_ftr" else "11342"), "CPU 315-2 PN/DP")))), 2)
        # Profinet DCP from the filter PLC (controller) and the HMIs (devices)
        self.rec(s, eth("01:0e:cf:00:00:00", D["plc_ftr"][0], 0x8892, self.profinet_dcp("filter-plc-01", "S7-300", 0x002A, 0x0101, D["plc_ftr"][1], "255.255.255.0", "10.20.1.1", role=0x02)), 4)
        self.rec(s, eth("01:0e:cf:00:00:00", D["hmi1"][0], 0x8892, self.profinet_dcp("hmi-filters", "SIMATIC HMI TP1200 Comfort", 0x002A, 0x0202, D["hmi1"][1], "255.255.255.0", "10.20.2.1", role=0x01)), 4)
        # EtherNet/IP: SCADA and HMI to the Rockwell high-service pump PLC; PLC answers ListIdentity
        self.flow(s, "scada1", "plc_hsp", 49300, 44818, n=160)
        self.flow(s, "hmi2", "plc_hsp", 49301, 44818, n=90)
        self.flow(s, "ews", "plc_hsp", 49302, 44818, n=15)
        mac, ip, _ = D["plc_hsp"]
        smac, sip, _ = D["scada1"]
        self.rec(s, eth(smac, mac, 0x0800, ipv4(ip, sip, 17, udp(44818, 49300, self.enip_list_identity("1756-L83E/B LOGIX5583E", 0x00A1B2C3)))), 3)
        self.flow(s, "plc_hsp", "hmi2", 2222, 2222, n=400, proto="udp", reply=False)  # implicit I/O
        # Modbus gateway (serial-to-IP) polled by SCADA; gateway identifies itself
        self.flow(s, "scada1", "moxa", 49400, 502, n=220)
        mac, ip, _ = D["moxa"]
        self.rec(s, eth(smac, mac, 0x0800, ipv4(ip, sip, 6, tcp(502, 49400, self.modbus_device_id()))), 2)
        # DNP3 from lift-station RTUs over the radio backhaul, arriving via the process switch
        for rtu, addr in (("rtu_ls7", 7), ("rtu_ls9", 9)):
            mac, ip, _ = D[rtu]
            self.rec(s, eth(smac, mac, 0x0800, ipv4(ip, sip, 6, tcp(20000, 49500, self.dnp3_unsolicited(addr, 1, 0x90 if rtu == "rtu_ls9" else 0x00)))), 30)
            self.rec(s, eth(mac, smac, 0x0800, ipv4(sip, ip, 6, tcp(49500, 20000, self.dnp3_read(1, addr)))), 30)
        # Historian collects from SCADA, replicates to the enterprise DC (crosses DMZ-less)
        self.flow(s, "hist", "scada1", 49600, 5450, n=300)
        self.flow(s, "dc", "hist", 50100, 445, n=60)          # SMB from enterprise into OT historian
        self.flow(s, "hist", "dc", 49601, 389, n=25)           # LDAP to enterprise AD
        self.flow(s, "hist", "dc", 123, 123, n=40, proto="udp")  # NTP
        # Enterprise workstation RDP straight to the SCADA server (bypassing any jump host)
        self.flow(s, "ad_ws", "scada1", 50200, 3389, n=45)
        # Vendor remote access: external IP RDP to EWS through the firewall (appears as firewall MAC)
        vendor = ("00:1a:a1:50:00:09", "203.0.113.34", "")
        self.flow(s, vendor, "ews", 51000, 3389, n=35)
        # Cleartext telnet from EWS to the process switch, HTTP to HMI web
        self.flow(s, "ews", "sw_proc", 50300, 23, n=8)
        self.flow(s, "ews", "hmi1", 50301, 80, n=6)
        hmac, hip, _ = D["hmi1"]; emac, eip, _ = D["ews"]
        self.rec(s, eth(emac, hmac, 0x0800, ipv4(hip, eip, 6, tcp(80, 50301, self.http_response("Siemens SIMATIC HMI Miniweb 15.1")))), 2)
        # A camera on the process VLAN talking to the internet
        cmac, cip, _ = D["cam"]
        self.rec(s, arp(cmac, cip, "10.20.9.1"), 2)
        self.flow(s, "cam", ("00:1a:a1:50:00:09", "203.0.113.9", ""), 50400, 443, n=140)
        # OPC UA from the historian (client) to SCADA-A's KEPServerEX (server): plaintext channel, anonymous allowed
        self.flow(s, "hist", "scada1", 49700, 4840, n=120)
        hmac, hip, _ = D["hist"]; smac, sip, _ = D["scada1"]
        self.rec(s, eth(smac, hmac, 0x0800, ipv4(hip, sip, 6, tcp(49700, 4840, self.opcua_hello("opc.tcp://wtp-scada-a.riverbend.local:4840")))), 2)
        self.rec(s, eth(smac, hmac, 0x0800, ipv4(hip, sip, 6, tcp(49700, 4840, self.opcua_open_channel("http://opcfoundation.org/UA/SecurityPolicy#None", "AVEVA Historian OPC UA Collector")))), 2)
        self.rec(s, eth(smac, hmac, 0x0800, ipv4(hip, sip, 6, tcp(49700, 4840, self.opcua_activate_anonymous()))), 2)
        self.rec(s, eth(smac, hmac, 0x0800, ipv4(hip, sip, 6, tcp(49700, 4840, self.opcua_create_session_request(
            "urn:WTP-HIST01:AVEVA:Historian", "urn:aveva.com:historian:opcua", "AVEVA Historian OPC UA collector", "urn:WTP-SCADA-A:Kepware.KEPServerEX.V6", "opc.tcp://wtp-scada-a.riverbend.local:4840")))), 2)
        self.rec(s, eth(hmac, smac, 0x0800, ipv4(sip, hip, 6, tcp(4840, 49700, self.opcua_get_endpoints_response(
            "opc.tcp://wtp-scada-a.riverbend.local:4840", "urn:WTP-SCADA-A:Kepware.KEPServerEX.V6", "urn:kepware.com:KEPServerEX", "KEPServerEX/UA Server",
            [(1, "http://opcfoundation.org/UA/SecurityPolicy#None", [0, 1]), (3, "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256", [1])])))), 2)
        # SCADA-A reads the HSP PLC's Identity object over explicit messaging (what RSLinx does on browse)
        pmac, pip, _ = D["plc_hsp"]
        req, rsp = self.enip_identity_exchange(b"RVBSCADA", 1, 0x0E, 0x0058, 20, 11, 0x00A1B2C3, "1756-L83E/B LOGIX5583E")
        self.rec(s, eth(pmac, smac, 0x0800, ipv4(sip, pip, 6, tcp(49302, 44818, req))), 1)
        self.rec(s, eth(smac, pmac, 0x0800, ipv4(pip, sip, 6, tcp(44818, 49302, rsp))), 1)
        self.flow(s, "dc", "sw_ctrl", 50500, 161, n=30, proto="udp")
        self.flow(s, "dc", "sw_proc", 50501, 161, n=30, proto="udp")
        st.end_session(s)
        return s

    def lift_station_access_port(self):
        st = self.store
        s = st.begin_session("Riverbend Regional Water Utility — OT assessment", "Lift Station 7", "LS-7 panel switch spare port", "eth0", "live", "Unconfirmed access port")
        mac, ip, _ = DEVICES["rtu_ls7"]
        self.rec(s, arp(mac, ip, "10.20.7.1"), 6, local="00:14:22:aa:00:01")
        self.rec(s, arp("00:14:22:aa:00:01", "10.20.7.200", "10.20.7.1"), 6, local="00:14:22:aa:00:01")
        self.rec(s, eth("01:80:c2:00:00:0e", "00:90:e8:70:00:01", 0x88CC, self.lldp("LS7-SW", "Moxa EDS-508A managed switch", "Port 8")), 10, local="00:14:22:aa:00:01")
        # RTU broadcast only; its DNP3 unicast to SCADA is not visible from an access port
        st.end_session(s)
        return s

    # ---- assessor data
    def documented_assets(self):
        rows = [
            "name,mac,ip,asset_tag,manufacturer,model,serial,firmware,device_type,location,criticality,purdue_level,zone,process_function,safety_impact,owner,source,install_date,end_of_life,end_of_support,support_status,patch_status,backup_status,last_backup,notes",
            'Safety PLC — chlorine room,,,OT-0210,Siemens,ET 200SP F-CPU 1512SP F,S C-K7E22398,V2.8,Safety PLC,Chlorine building panel CL-1,Critical,Level 1,Chemical feed cell,Chlorine leak detection and feed shutdown,Loss of automatic chlorine isolation,OT engineering,Physical walkdown,2019-04,,,Supported,Vendor patch V2.9 available; not applied,Backed up and tested,2026-06-12,"Not on Ethernet; PROFIsafe over PROFIBUS to CHEM-PLC-02"',
            'LS-9 RTU,00:30:a7:40:00:72,10.20.7.72,OT-0709,Schweitzer Engineering Laboratories,SEL-3505,3505-1907-0331,R117,RTU,Lift station 9 cabinet,High,Level 1,Remote sites,Pump control and wet-well telemetry,Sewage overflow if station trips without telemetry,Operations,Physical walkdown,2015-08,2024-12-31,2026-12-31,Extended support,No patches since 2023,No backup,,"Settings file last exported 2021 per operator"',
            'LS-7 RTU,00:30:a7:40:00:71,10.20.7.71,OT-0707,Schweitzer Engineering Laboratories,SEL-3505,3505-1907-0298,R117,RTU,Lift station 7 cabinet,High,Level 1,Remote sites,Pump control and wet-well telemetry,Sewage overflow if station trips without telemetry,Operations,Physical walkdown,2015-08,2024-12-31,2026-12-31,Extended support,No patches since 2023,Unknown,,',
            'LS-7 radio,,,OT-0708,Cambium,PTP 450i,,,Radio,Lift station 7 mast,High,Level 1,Remote sites,Telemetry backhaul to WTP,Loss of remote visibility and control,Operations,Physical walkdown,2016-02,,,Unknown,Unknown,Not applicable,,"Licensed 900 MHz link; no encryption confirmed"',
            'Filter gallery flow meter,,,OT-0330,Endress+Hauser,Promag 400,,,Instrument,Filter gallery,Moderate,Level 0,Filtration cell,Filtered water flow,Loss of flow measurement; manual reading,OT engineering,Drawing / documentation,2018-11,,,Supported,,Not applicable,,"Modbus RTU serial to MGate MB3170 gateway"',
            'Chlorine residual analyser,,,OT-0331,Hach,CL17sc,,,Instrument,Chlorine building,High,Level 0,Chemical feed cell,Residual chlorine measurement,Compliance sample failure,OT engineering,Drawing / documentation,2020-05,,,Supported,,Not applicable,,"4-20 mA to CHEM-PLC-02"',
            'High-service pump VFD 1,,,OT-0340,ABB,ACS880,,2.9,Drive,Pump room MCC-3,Critical,Level 1,High-service pumping,Distribution pressure,Loss of distribution pressure; boil-water risk,OT engineering,Physical walkdown,2017-09,,,Supported,,Not applicable,,"EtherNet/IP I/O to HSP PLC via implicit connection"',
            'Spare S7-300 CPU,,,OT-0901,Siemens,6ES7 315-2EH14-0AB0,S C-D4X09811,V3.2.7,PLC spare,Stores cage B,Moderate,,,Cold spare for filter and chemical PLCs,,OT engineering,Interview,2016-01,2023-10-01,2025-10-01,End of support,,Not applicable,,"Confirmed in stores; no second spare"',
            'Cellular modem LS-9,,,OT-0710,Sierra Wireless,AirLink RV50X,,,Cellular modem,Lift station 9 cabinet,High,Level 1,Remote sites,Backup telemetry path,Loss of backup path,Operations,Interview,2021-03,,,Supported,Firmware unknown,Not applicable,,"Carrier APN; management password reported as default"',
        ]
        result = self.store.import_assets_csv("\n".join(rows).encode("utf-8"), "Physical walkdown")
        assert not result["errors"], result["errors"]
        names = {"plc_ftr": "FILTER-PLC-01", "plc_chem": "CHEM-PLC-02", "plc_hsp": "HSP-PLC-03", "moxa": "FP3-MGATE-01", "cam": "Unknown camera (Gi1/14)",
                 "sw_ctrl": "WTP-CORE-SW1", "sw_proc": "WTP-PROC-SW2", "fw": "WTP-OTFW-1", "ad_ws": "ADMIN-PC-214", "dc": "RVB-DC01",
                 "scada1": "WTP-SCADA-A", "scada2": "WTP-SCADA-B", "hist": "WTP-HIST01", "ews": "WTP-EWS01", "hmi1": "WTP-HMI-FILTERS", "hmi2": "WTP-HMI-CHEM"}
        for key, name in names.items():
            self.store.add_documented_asset({"name": name, "mac": DEVICES[key][0], "source": "Physical walkdown"})
        self.store.add_documented_asset({"name": "LS7-SW", "mac": "00:90:e8:70:00:01", "manufacturer": "Moxa Technologies", "model": "EDS-508A", "device_type": "Managed switch (panel)", "location": "Lift station 7 cabinet", "criticality": "High", "owner": "Operations", "source": "Physical walkdown", "notes": "Spare port 8 active and unsecured"})
        self.store.add_documented_asset({"name": "Assessor collector laptop", "mac": COLLECTOR, "device_type": "Assessment collector (not client asset)", "source": "Interview", "notes": "OT Scout capture laptop; exclude from client inventory"})

    def context(self):
        st = self.store
        by_mac = {a["mac"]: a for a in st.assets()}
        ctx = {
            "scada1": dict(manual_type="SCADA server (primary)", location="Control room rack CR-1", criticality="Critical", purdue_level="Level 2", zone="Supervisory control", process_function="Plant-wide SCADA (GE iFIX)", owner="OT engineering", safety_impact="Loss of plant supervisory control; manual operation", vendor="Dell Inc.", model="PowerEdge R640", support_status="Supported", patch_status="Windows Server 2016; last patched 2024-11", backup_status="Backed up, untested", last_backup="2026-08-30"),
            "scada2": dict(manual_type="SCADA server (standby)", location="Control room rack CR-1", criticality="Critical", purdue_level="Level 2", zone="Supervisory control", process_function="SCADA redundant node", owner="OT engineering", vendor="Dell Inc.", model="PowerEdge R640", support_status="Supported", patch_status="Windows Server 2016; last patched 2024-11", backup_status="Backed up, untested", last_backup="2026-08-30"),
            "hist": dict(manual_type="Historian", location="Control room rack CR-1", criticality="High", purdue_level="Level 3", zone="Site operations", process_function="Process historian (AVEVA PI)", owner="OT engineering", vendor="Dell Inc.", model="PowerEdge R740", support_status="Supported", patch_status="Windows Server 2019; last patched 2025-02", backup_status="Backed up and tested", last_backup="2026-08-31"),
            "ews": dict(manual_type="Engineering workstation", location="Control room desk 2", criticality="High", purdue_level="Level 3", zone="Site operations", process_function="TIA Portal / Studio 5000 engineering", owner="OT engineering", vendor="Hewlett Packard", model="Z2 G9", support_status="Supported", patch_status="Windows 10; last patched 2023-07", backup_status="No backup"),
            "hmi1": dict(manual_type="HMI", location="Filter gallery panel FP-1", criticality="High", purdue_level="Level 2", zone="Filtration cell", process_function="Filter operator interface", owner="Operations", vendor="Siemens AG", model="SIMATIC HMI TP1200 Comfort", support_status="Supported", backup_status="Backed up, untested", last_backup="2025-11-04"),
            "hmi2": dict(manual_type="HMI", location="Chemical building panel CH-1", criticality="High", purdue_level="Level 2", zone="Chemical feed cell", process_function="Chemical dosing interface", owner="Operations", vendor="Siemens AG", model="SIMATIC HMI TP1200 Comfort", support_status="Supported", backup_status="Backed up, untested", last_backup="2025-11-04"),
            "plc_ftr": dict(manual_type="PLC", location="Filter gallery panel FP-3", criticality="Critical", purdue_level="Level 1", zone="Filtration cell", process_function="Filter sequencing and backwash", owner="OT engineering", safety_impact="Loss of filtration; manual operation required", support_status="End of support", install_date="2014-06", end_of_life="2023-10-01", end_of_support="2025-10-01", patch_status="No vendor firmware updates available", backup_status="Backed up, untested", last_backup="2026-03-15"),
            "plc_chem": dict(manual_type="PLC", location="Chemical building panel CH-3", criticality="Critical", purdue_level="Level 1", zone="Chemical feed cell", process_function="Coagulant and chlorine dosing", owner="OT engineering", safety_impact="Overdose/underdose of chemicals; compliance breach", support_status="End of support", install_date="2014-06", end_of_life="2023-10-01", end_of_support="2025-10-01", patch_status="No vendor firmware updates available", backup_status="Backed up and tested", last_backup="2026-06-12"),
            "plc_hsp": dict(manual_type="PLC", location="Pump room MCC-3", criticality="Critical", purdue_level="Level 1", zone="High-service pumping", process_function="High-service pump control", owner="OT engineering", safety_impact="Loss of distribution pressure", support_status="Supported", install_date="2021-02", patch_status="Firmware 20.011; current", backup_status="Backed up and tested", last_backup="2026-08-01"),
            "moxa": dict(manual_type="Serial-to-IP gateway", location="Filter gallery panel FP-3", criticality="Moderate", purdue_level="Level 1", zone="Filtration cell", process_function="Modbus RTU instruments to SCADA", owner="OT engineering", support_status="Supported", backup_status="Unknown"),
            "sw_ctrl": dict(manual_type="Managed switch (core)", location="Control room rack CR-2", criticality="Critical", zone="Site operations", owner="IT network", vendor="Cisco Systems", model="IE-4000", firmware="IOS 15.2(7)E4", support_status="Supported", backup_status="Backed up and tested", last_backup="2026-07-20"),
            "sw_proc": dict(manual_type="Managed switch (process)", location="Filter gallery panel FP-2", criticality="Critical", zone="Filtration cell", owner="IT network", vendor="Cisco Systems", model="IE-3400", firmware="IOS-XE 17.6", support_status="Supported", backup_status="Backed up and tested", last_backup="2026-07-20"),
            "fw": dict(manual_type="OT firewall", location="Control room rack CR-2", criticality="Critical", purdue_level="Industrial DMZ", zone="IT/OT boundary", owner="IT security", vendor="Cisco Systems", model="Firepower 1120", firmware="FTD 7.2", support_status="Supported", backup_status="Backed up and tested", last_backup="2026-08-15"),
            "dc": dict(manual_type="Domain controller (enterprise)", location="Admin building data room", criticality="High", purdue_level="Level 4", zone="Enterprise", process_function="Enterprise AD, NTP, NMS", owner="IT", vendor="Dell Inc.", model="PowerEdge R650"),
            "ad_ws": dict(manual_type="Enterprise workstation", location="Admin building office 214", criticality="Low", purdue_level="Level 4", zone="Enterprise", process_function="Plant manager desktop", owner="IT", vendor="Dell Inc.", model="OptiPlex 7090"),
            "cam": dict(manual_type="IP camera (consumer)", location="Filter gallery — unlabelled", criticality="Low", purdue_level="Level 1", zone="Filtration cell", process_function="Unknown; not on drawings", owner="Unknown", notes="Found during walkdown plugged into FP-2 spare port; not on any drawing or inventory"),
        }
        for key, values in ctx.items():
            mac = DEVICES[key][0]
            values.setdefault("source", "Physical walkdown")
            st.update_asset(by_mac[mac]["id"], values)
        st.update_asset(by_mac[COLLECTOR]["id"], {"location": "Assessor", "owner": "Assessment team"})

    def site_validation(self):
        st = self.store
        site = st.save_site({"assessment": "Riverbend Regional Water Utility — OT assessment", "name": "Main WTP", "facility_type": "Surface-water treatment plant, 24 MGD",
                             "operational_function": "Sole potable supply for the service area; loss of high-service pumping causes distribution pressure loss within 2 hours",
                             "contacts": "Plant superintendent; OT engineer (SCADA); IT network lead; integrator (Gulf Automation)", "walkdown_date": "2026-08-27",
                             "documentation": "P&IDs (2019 rev), network drawing WTP-NET-004 (2021), switch configs for CORE-SW1/PROC-SW2, firewall rule export, PI tag list, SCADA I/O list",
                             "deviations": "Drawing WTP-NET-004 shows an OT DMZ between historian and enterprise; observed traffic shows historian talking directly to the enterprise domain controller. Unlabelled consumer camera on PROC-SW2 port Gi1/14 not on drawings."})
        sid = site["id"]
        checklist = {
            "facility_function": ("Complete", "Interview 2026-08-27; P&ID set", ""),
            "ingress_egress": ("Complete", "Firewall rule export; drawing WTP-NET-004; radio site survey", "Radio backhaul and LS-9 cellular modem are ingress points not shown on the drawing"),
            "asset_categories": ("Complete", "Walkdown photos 001-118; asset spreadsheet", ""),
            "scada_historian": ("Complete", "SCADA architecture interview; PI server review", "Redundancy via iFIX SCADA-B; failover last tested 2024"),
            "remote_access": ("In progress", "Firewall rules; vendor access log request outstanding", "Integrator has standing RDP path to EWS; approval workflow undocumented"),
            "telemetry": ("Complete", "Radio survey; RTU settings review", "Unencrypted 900 MHz PTP links to LS-7/LS-9"),
            "documentation": ("Complete", "Documents listed above", "Drawing is 5 years old"),
            "interviews": ("Complete", "Superintendent, OT engineer, IT network lead, two operators", ""),
            "config_review": ("In progress", "Switch configs reviewed; firewall review scheduled", "No NetFlow; no SPAN configured before this assessment; no continuous OT monitoring platform"),
            "walkdown": ("Complete", "Photos 001-118; panel schedule", "All panels except LS-9 (access pending)"),
            "safety": ("Complete", "Site induction 2026-08-26; escort throughout", ""),
        }
        for item, (status, evidence, notes) in checklist.items():
            st.save_checklist_item(sid, item, {"status": status, "evidence": evidence, "notes": notes})
        st.save_leg(sid, {"name": "Control room / supervisory LAN", "description": "SCADA, historian, EWS, core switch", "purdue_level": "Level 2-3", "evidence_source": "Configured SPAN/mirror", "collection_point": "Control room core switch SPAN", "status": "Collected", "time_window": "2026-08-27 09:10–12:40", "exclusions": "", "limitations": "SPAN on CORE-SW1 only; PROC-SW2 uplink traffic seen, intra-PROC-SW2 traffic not seen"})
        st.save_leg(sid, {"name": "Process VLAN (filters, chemical, pumps)", "description": "PLCs, HMIs, gateway on PROC-SW2", "purdue_level": "Level 1-2", "evidence_source": "Switch tables / ARP", "collection_point": "", "status": "Partial", "time_window": "", "exclusions": "", "limitations": "No SPAN available on PROC-SW2; MAC table and drawings only for intra-VLAN traffic"})
        st.save_leg(sid, {"name": "Radio telemetry backhaul", "description": "PTP 450i links to LS-7 and LS-9", "purdue_level": "Level 1", "evidence_source": "Drawings and interviews only", "collection_point": "", "status": "Partial", "limitations": "RTU DNP3 observed at control room; link-layer security not verifiable passively"})
        st.save_leg(sid, {"name": "Enterprise / IT boundary", "description": "Firewall between OT and enterprise", "purdue_level": "Industrial DMZ", "evidence_source": "NetFlow / firewall logs", "collection_point": "", "status": "Planned", "limitations": "Firewall log export requested; not yet received"})
        site2 = st.save_site({"assessment": "Riverbend Regional Water Utility — OT assessment", "name": "Lift Station 7", "facility_type": "Sewage lift station, 2 pumps", "operational_function": "Wet-well level control; overflow to creek on failure", "contacts": "Operations lead", "walkdown_date": "2026-08-28", "documentation": "Panel schedule; RTU settings export", "deviations": "Spare Ethernet port on panel switch active and unsecured; cellular modem not on drawing"})
        for item in ("facility_function", "asset_categories", "telemetry", "walkdown", "safety"):
            st.save_checklist_item(site2["id"], item, {"status": "Complete", "evidence": "Walkdown 2026-08-28; photos 201-224", "notes": ""})
        for item in ("scada_historian", "config_review", "interviews"):
            st.save_checklist_item(site2["id"], item, {"status": "Not applicable", "evidence": "", "notes": "Covered at Main WTP"})
        st.save_leg(site2["id"], {"name": "LS-7 panel LAN", "description": "RTU, radio, panel switch", "purdue_level": "Level 1", "evidence_source": "Unconfirmed access port", "collection_point": "LS-7 panel switch spare port", "status": "Collected", "time_window": "2026-08-28 10:05–10:50", "limitations": "Access port: only broadcast and traffic to the collector visible"})

    def conduits(self):
        st = self.store
        by_mac = {a["mac"]: a["id"] for a in st.assets()}
        aid = lambda key: f"asset:{by_mac[DEVICES[key][0]]}"
        decisions = [
            (("scada1", "plc_ftr"), "Approved", "SCADA polling filter PLC (S7)"), (("scada1", "plc_chem"), "Approved", "SCADA polling chemical PLC (S7)"),
            (("scada2", "plc_ftr"), "Approved", "Standby SCADA polling"), (("scada2", "plc_chem"), "Approved", "Standby SCADA polling"),
            (("ews", "plc_ftr"), "Approved", "Engineering access (TIA Portal)"), (("ews", "plc_chem"), "Approved", "Engineering access (TIA Portal)"),
            (("scada1", "plc_hsp"), "Approved", "SCADA to HSP PLC (EtherNet/IP)"), (("hmi2", "plc_hsp"), "Approved", "HMI to HSP PLC; implicit I/O"),
            (("ews", "plc_hsp"), "Approved", "Engineering access (Studio 5000)"), (("scada1", "moxa"), "Approved", "SCADA polling serial gateway (Modbus/TCP)"),
            (("scada1", "rtu_ls7"), "Approved", "DNP3 telemetry LS-7"), (("scada1", "rtu_ls9"), "Approved", "DNP3 telemetry LS-9"),
            (("hist", "scada1"), "Approved", "Historian collection (iFIX / OPC UA)"),
            (("dc", "hist"), "Unexpected", "Enterprise DC opens SMB into OT historian; historian joined to enterprise AD (LDAP/NTP). Drawing shows a DMZ here."),
            (("ad_ws", "scada1"), "Unexpected", "Plant manager workstation RDP direct to SCADA-A; no jump host"),
            (("ews", "sw_proc"), "Tolerated", "Telnet switch management — replace with SSH"),
            (("ews", "hmi1"), "Approved", "HMI web diagnostics"),
            (("dc", "sw_ctrl"), "Tolerated", "Enterprise NMS SNMP polling of OT switches"), (("dc", "sw_proc"), "Tolerated", "Enterprise NMS SNMP polling of OT switches"),
        ]
        for (a, b), decision, purpose in decisions:
            ka, kb = sorted((aid(a), aid(b)))
            st.save_conduit(ka, kb, {"decision": decision, "purpose": purpose})
        for r in st.relationships(100000):
            if r["endpoint_b"] == "203.0.113.34" or r["endpoint_a"] == "203.0.113.34":
                st.save_conduit(r["key_a"], r["key_b"], {"decision": "Tolerated", "purpose": "Integrator remote support (RDP) — approval process undocumented"})
            if "203.0.113.9" in (r["endpoint_a"], r["endpoint_b"]):
                st.save_conduit(r["key_a"], r["key_b"], {"decision": "Unexpected", "purpose": "Unknown camera streaming to internet from process VLAN"})
        st.accept_suggested_levels(min_confidence=50)
        st.update_asset(by_mac[COLLECTOR], {"purdue_level": ""})  # the assessor laptop is not a client asset

    def findings(self):
        st = self.store
        from ot_scout.report import Analysis
        drafts = Analysis(collect(st), False).drafts
        st.import_draft_findings(drafts)
        for f in st.findings():
            updates = {"id": f["id"], "status": "Validated"}
            if f["kind"] == "Positive observation":
                updates["status"] = "Validated"
            if "Passive visibility" in f["title"]:
                updates.update(status="Rejected", notes="SPAN was configured on CORE-SW1; leg-specific coverage is covered by OBS on network legs")
            if "Multiple IPv4 subnets" in f["title"]:
                updates.update(status="Rejected")  # core-switch SPAN legitimately carries several VLANs
            if "Network legs" in f["title"]:
                updates.update(owner="IT network lead", horizon="Immediate / quick win", status="Validated")
            if "unexpected" in f["title"].lower():
                updates.update(kind="Control deficiency", rating="High priority", owner="IT security / OT engineering", horizon="Immediate / quick win",
                               title="Enterprise-to-OT communications bypass the documented industrial DMZ",
                               condition="The historian is joined to the enterprise Active Directory and receives SMB sessions from the enterprise domain controller; the plant manager's enterprise workstation opens RDP directly to the primary SCADA server. Drawing WTP-NET-004 shows an OT DMZ that these flows do not traverse.",
                               impact="A compromise of any enterprise host or account (phishing, commodity malware) has an authenticated path to the SCADA server and historian without touching a DMZ control. This is the single most likely path from the business network to the process.",
                               recommendation="Terminate historian replication and remote access in the industrial DMZ (PI-to-PI or replica, RDP jump host with MFA); remove direct AD trust from OT servers or move them to an OT domain; block enterprise-to-OT SMB/RDP at WTP-OTFW-1.",
                               closure="No enterprise-to-OT SMB, RDP or LDAP sessions observed at the OT firewall; historian and SCADA reachable only via DMZ brokers.")
            if "Cleartext" in f["title"]:
                updates.update(kind="Control deficiency", rating="Moderate", owner="IT network lead", horizon="30-90 days")
            if "End-of-life" in f["title"]:
                updates.update(kind="Control deficiency", rating="High priority", horizon="3-12 months", owner="OT engineering")
            if "backups" in f["title"]:
                updates.update(kind="Control deficiency", rating="High priority", horizon="Immediate / quick win", owner="OT engineering")
            if "Industrial protocols observed" in f["title"]:
                updates.update(status="Validated", horizon="30-90 days")
            st.save_finding(updates)
        st.save_finding({"title": "Unknown consumer IP camera connected to the process VLAN and streaming to the internet", "kind": "Control deficiency", "rating": "Critical", "confidence": "High",
                         "owner": "OT engineering / plant superintendent", "horizon": "Immediate / quick win", "status": "Validated", "site": "Main WTP", "assets": "d0:3f:27:70:00:01 on PROC-SW2 Gi1/14",
                         "condition": "A Wyze consumer camera with no owner, not on any drawing or inventory, was found plugged into a spare port on the process switch during the walkdown. It maintains an outbound HTTPS session to a public cloud endpoint.",
                         "evidence": "Walkdown photo 087; passive capture: 140 packets to 203.0.113.9:443 from 10.20.9.101; port Gi1/14 not shut down; no 802.1X or port security on PROC-SW2.",
                         "impact": "An internet-connected device of unknown provenance sits on the same VLAN as the filter and chemical PLCs. Any remote compromise of the camera is a foothold inside the process zone.",
                         "recommendation": "Remove the camera immediately and shut down unused switch ports; add port security or 802.1X on PROC-SW2; if plant CCTV is required, place it on a separate VLAN behind the firewall.",
                         "closure": "Device removed; unused ports shut; port-security policy documented and verified on all OT switches.",
                         "iec62443": format_refs(["SR 5.1", "SR 5.2", "SR 1.2", "SR 7.8"]), "attack": format_refs(["T0883", "T0884", "T0886"])})
        st.save_finding({"title": "Vendor remote access to the engineering workstation has no approval workflow or session control", "kind": "Control deficiency", "rating": "High priority", "confidence": "Moderate",
                         "owner": "IT security / OT engineering", "horizon": "30-90 days", "status": "Validated", "site": "Main WTP", "assets": "WTP-EWS01; WTP-OTFW-1",
                         "condition": "The integrator holds a standing RDP path from a public address (203.0.113.34) through the OT firewall to the engineering workstation. Staff could not describe how sessions are requested, approved, time-limited or recorded.",
                         "evidence": "Firewall rule export (rule 14, any time); 35 RDP packets observed during the capture window; interview with OT engineer.",
                         "impact": "The engineering workstation can download logic to every PLC. Unmanaged vendor access is the most common initial access vector in reported water-sector incidents.",
                         "recommendation": "Route vendor access through a DMZ jump host with MFA, per-session enablement by plant staff, session recording and automatic expiry; disable rule 14.",
                         "closure": "No direct external-to-EWS rule; vendor sessions logged with approver and duration.",
                         "iec62443": format_refs(["SR 1.13", "SR 2.6", "SR 5.2", "2-4 SP.07"]), "attack": format_refs(["T0822", "T0886", "T0843"])})
        st.save_finding({"title": "Lift-station telemetry radios operate without link encryption and RTU settings are not backed up", "kind": "Control deficiency", "rating": "Moderate", "confidence": "Moderate",
                         "owner": "Operations / OT engineering", "horizon": "3-12 months", "status": "Validated", "site": "Lift Station 7", "assets": "LS-7 RTU, LS-9 RTU, PTP 450i radios, LS-9 cellular modem",
                         "condition": "DNP3 telemetry from LS-7 and LS-9 crosses licensed 900 MHz links whose encryption could not be confirmed; the LS-9 cellular backup modem reportedly retains its default management password; RTU settings were last exported in 2021.",
                         "evidence": "Radio survey; interview; RTU IIN flags showed 'device restart' and 'need time' on LS-9, suggesting an unstable or unsynchronised unit.",
                         "impact": "Spoofed or replayed DNP3 could operate pumps; an RTU failure would require rebuilding settings from memory.",
                         "recommendation": "Enable radio link encryption; change modem credentials and restrict management to the OT network; export and store RTU settings quarterly; investigate the LS-9 restart indication.",
                         "closure": "Encryption enabled and verified; modem hardened; RTU settings archived with restore test.",
                         "iec62443": format_refs(["SR 3.1", "SR 1.6", "SR 1.5", "SR 7.3"]), "attack": format_refs(["T0830", "T0855", "T0812"])})
        st.save_finding({"title": "No continuous OT network monitoring; visibility for this assessment was created by a temporary SPAN", "kind": "Improvement opportunity", "rating": "Moderate", "confidence": "High",
                         "owner": "IT security", "horizon": "3-12 months", "status": "Validated", "site": "Main WTP",
                         "condition": "The utility has no passive OT monitoring platform, no NetFlow from OT switches and no SPAN/TAP infrastructure beyond the temporary mirror configured for this assessment.",
                         "evidence": "Site-validation checklist (configuration and log review); interview with IT network lead.",
                         "impact": "Changes such as the unknown camera or the direct enterprise-to-SCADA sessions would not be detected between assessments.",
                         "recommendation": "Make the CORE-SW1 SPAN permanent and add one on PROC-SW2; evaluate a passive OT monitoring platform fed from those SPANs with alerts into the existing SOC/SIEM.",
                         "closure": "Permanent SPAN/TAP feeds in place; monitoring platform or equivalent detection in operation with alert routing.",
                         "iec62443": format_refs(["SR 6.2", "SR 2.8"]), "attack": ""})
        st.save_finding({"title": "Historian and SCADA redundancy, backups and switch configurations are in place and tested", "kind": "Positive observation", "rating": "Positive", "confidence": "High",
                         "owner": "OT engineering", "horizon": "Not applicable", "status": "Validated", "site": "Main WTP",
                         "condition": "SCADA runs as a redundant pair; the historian, HSP PLC, chemical PLC and both managed switches have current, tested backups.",
                         "evidence": "Backup records reviewed; restore test log 2026-06-12.", "impact": "Recovery of core supervisory functions is credible.",
                         "recommendation": "Extend the same regime to the filter PLC, HMIs, EWS and RTUs.", "closure": "Not applicable.",
                         "iec62443": format_refs(["SR 7.3", "SR 7.4"]), "attack": ""})


def set_session_times(store, session_id, start, end):
    with store.lock, store.connect() as db:
        db.execute("UPDATE sessions SET started_at=?,ended_at=? WHERE id=?", (start, end, session_id))
    store._bump()


def build_demo(path: Path = DB) -> "Demo":
    """Build the complete demonstration database at `path` and return the Demo (with .store)."""
    demo = Demo(path)
    s1 = demo.control_room_span()
    s2 = demo.lift_station_access_port()
    set_session_times(demo.store, s1, "2026-08-27T13:10:00+00:00", "2026-08-27T16:40:00+00:00")
    set_session_times(demo.store, s2, "2026-08-28T14:05:00+00:00", "2026-08-28T14:50:00+00:00")
    demo.documented_assets()
    demo.context()
    demo.site_validation()
    demo.conduits()
    demo.findings()
    return demo


def main():
    demo = build_demo(DB)
    if False:
        s1 = demo.control_room_span()
    out = Path(__file__).parent / "demo-report.docx"
    meta = {"prepared_for": "Riverbend Regional Water Utility (fictitious — demonstration only)", "prepared_by": "Chris Hyatt, OT Assessment SME",
            "title": "OT / ICS Cybersecurity and Site Assessment", "banner": "DEMONSTRATION — ALL DATA FICTITIOUS", "sanitize": False}
    out.write_bytes(build_report(collect(demo.store), meta))
    (Path(__file__).parent / "demo-purdue.svg").write_text(demo.store.purdue_svg())
    z = demo.store.zone_summary()
    print(f"Demo database: {DB}")
    print(f"Assets: {demo.store.dashboard()['assets']} physical / {len(demo.store.assets())} identities; relationships: {len(demo.store.relationships())}; findings: {len(demo.store.findings())}")
    print(f"Zones: {z['assigned']}/{z['physical'] - z['infrastructure']} assigned, {z['unexpected']} unexpected conduits, {z['unreviewed_crossings']} unreviewed crossings")
    print(f"Report: {out}\nDiagram: demo-purdue.svg\nRun the app on it with: sudo python3 run.py --database data/demo.db")


if __name__ == "__main__":
    main()
