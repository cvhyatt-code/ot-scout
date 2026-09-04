from __future__ import annotations

import ipaddress
import socket
import struct
from dataclasses import dataclass, field


APP_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    102: "S7COMM", 110: "POP3", 123: "NTP", 135: "MS-RPC",
    137: "NETBIOS-NS", 138: "NETBIOS-DGM", 139: "NETBIOS-SSN",
    161: "SNMP", 162: "SNMP-TRAP", 179: "BGP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 502: "MODBUS-TCP", 514: "SYSLOG",
    636: "LDAPS", 1883: "MQTT", 2222: "ETHERNET-IP-IO",
    3389: "RDP", 44818: "ETHERNET-IP", 47808: "BACNET-IP",
    4840: "OPC-UA", 5353: "MDNS", 5355: "LLMNR", 5900: "VNC",
    8883: "MQTT-TLS", 20000: "DNP3",
}


@dataclass
class PacketObservation:
    timestamp: float
    length: int
    src_mac: str
    dst_mac: str
    ethertype: int
    vlan: int | None = None
    src_ip: str = ""
    dst_ip: str = ""
    transport: str = "OTHER"
    src_port: int | None = None
    dst_port: int | None = None
    app_protocol: str = ""
    source_name: str = ""
    name_claims: list[tuple[str, str]] = field(default_factory=list)
    fingerprints: list[tuple[str, str, str, int]] = field(default_factory=list)


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _is_unicast_mac(value: str) -> bool:
    if not value or value == "00:00:00:00:00:00":
        return False
    first = int(value[:2], 16)
    return not (first & 1)


def _is_endpoint_ip(value: str) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return False


def _app_protocol(src_port: int | None, dst_port: int | None, transport: str) -> str:
    for port in (dst_port, src_port):
        if port in APP_PORTS:
            return APP_PORTS[port]
    return transport


def _dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 12:
        raise ValueError("DNS compression loop")
    labels: list[str] = []
    original_next = None
    while True:
        if offset >= len(data):
            raise ValueError("truncated DNS name")
        size = data[offset]
        if size == 0:
            offset += 1
            break
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = ((size & 0x3F) << 8) | data[offset + 1]
            if original_next is None:
                original_next = offset + 2
            suffix, _ = _dns_name(data, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            offset += 2
            break
        if size > 63 or offset + 1 + size > len(data):
            raise ValueError("invalid DNS label")
        label = data[offset + 1:offset + 1 + size].decode("utf-8", "replace")
        labels.append(label)
        offset += 1 + size
    return ".".join(labels).rstrip("."), original_next or offset


def _dns_claims(payload: bytes) -> list[tuple[str, str]]:
    if len(payload) < 12:
        return []
    try:
        flags, qd, an, ns, ar = struct.unpack("!HHHHH", payload[2:12])
        if not flags & 0x8000:
            return []
        offset = 12
        for _ in range(qd):
            _, offset = _dns_name(payload, offset)
            offset += 4
        claims: list[tuple[str, str]] = []
        for _ in range(an + ns + ar):
            name, offset = _dns_name(payload, offset)
            if offset + 10 > len(payload):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", payload[offset:offset + 10])
            offset += 10
            if offset + rdlen > len(payload):
                break
            rdata = payload[offset:offset + rdlen]
            if rtype == 1 and rdlen == 4:
                claims.append((socket.inet_ntop(socket.AF_INET, rdata), name))
            elif rtype == 28 and rdlen == 16:
                claims.append((socket.inet_ntop(socket.AF_INET6, rdata), name))
            offset += rdlen
        return claims[:32]
    except (ValueError, struct.error, OSError):
        return []


def _clean_text(value: bytes, limit: int = 255) -> str:
    return "".join(ch for ch in value.decode("utf-8", "replace") if ch.isprintable()).strip()[:limit]


def _dhcp_details(payload: bytes) -> tuple[str, list[tuple[str, str, str, int]]]:
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return "", []
    hostname = ""
    claims: list[tuple[str, str, str, int]] = []
    offset = 240
    while offset < len(payload):
        code = payload[offset]
        offset += 1
        if code == 255:
            break
        if code == 0:
            continue
        if offset >= len(payload):
            break
        size = payload[offset]
        offset += 1
        value = payload[offset:offset + size]
        offset += size
        if code == 12:
            hostname = _clean_text(value)
        elif code == 60 and value:
            claims.append(("dhcp_vendor_class", _clean_text(value), "DHCP option 60", 85))
        elif code == 55 and value:
            claims.append(("dhcp_parameter_signature", "-".join(str(item) for item in value), "DHCP option 55", 70))
    return hostname, claims


def _http_fingerprints(payload: bytes) -> list[tuple[str, str, str, int]]:
    if not payload:
        return []
    text = payload[:8192].decode("iso-8859-1", "replace")
    first = text.split("\r\n", 1)[0]
    if not (first.startswith("HTTP/") or first.split(" ", 1)[0] in {"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"}):
        return []
    headers = {}
    for line in text.split("\r\n")[1:100]:
        if not line:
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()[:255]
    result = []
    if first.startswith("HTTP/") and headers.get("server"):
        result.append(("software", headers["server"], "HTTP Server header", 80))
    elif headers.get("user-agent"):
        result.append(("client_software", headers["user-agent"], "HTTP User-Agent", 70))
    return result


def _lldp_fingerprints(payload: bytes) -> list[tuple[str, str, str, int]]:
    offset = 0
    result = [("role", "Network infrastructure", "LLDP", 90)]
    fields = {4: "port_description", 5: "system_name", 6: "system_description"}
    while offset + 2 <= len(payload):
        header = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2
        kind, size = header >> 9, header & 0x1FF
        if offset + size > len(payload):
            break
        value = payload[offset:offset + size]
        offset += size
        if kind == 0:
            break
        if kind in fields and value:
            result.append((fields[kind], _clean_text(value), f"LLDP TLV {kind}", 95))
    return result


def _modbus_fingerprints(payload: bytes) -> list[tuple[str, str, str, int]]:
    if len(payload) < 14 or payload[2:4] != b"\x00\x00":
        return []
    pdu = payload[7:]
    if len(pdu) < 7 or pdu[0:2] != b"\x2b\x0e":
        return []
    fields = {0: "manufacturer", 1: "product_code", 2: "firmware", 3: "vendor_url", 4: "product_name", 5: "model", 6: "application"}
    offset, count = 7, pdu[6]
    result = [("role", "Modbus device", "Modbus Read Device Identification", 90)]
    for _ in range(count):
        if offset + 2 > len(pdu):
            break
        object_id, size = pdu[offset], pdu[offset + 1]
        offset += 2
        if offset + size > len(pdu):
            break
        value = _clean_text(pdu[offset:offset + size])
        offset += size
        if value and object_id in fields:
            result.append((fields[object_id], value, f"Modbus device ID object {object_id}", 98))
    return result


def _enip_fingerprints(payload: bytes) -> list[tuple[str, str, str, int]]:
    if len(payload) < 32 or struct.unpack("<H", payload[:2])[0] != 0x0063:
        return []
    count = struct.unpack("<H", payload[24:26])[0]
    offset = 26
    for _ in range(min(count, 16)):
        if offset + 4 > len(payload):
            break
        item_type, size = struct.unpack("<HH", payload[offset:offset + 4])
        data = payload[offset + 4:offset + 4 + size]
        offset += 4 + size
        if item_type != 0x000C or len(data) < 34:
            continue
        base = 18
        vendor_id, device_type, product_code = struct.unpack("<HHH", data[base:base + 6])
        major, minor = data[base + 6], data[base + 7]
        serial = struct.unpack("<I", data[base + 10:base + 14])[0]
        name_size = data[base + 14]
        name = _clean_text(data[base + 15:base + 15 + name_size])
        result = [
            ("role", "EtherNet/IP device", "EtherNet/IP ListIdentity", 95),
            ("vendor_id", str(vendor_id), "EtherNet/IP ListIdentity", 98),
            ("device_type", str(device_type), "EtherNet/IP ListIdentity", 98),
            ("product_code", str(product_code), "EtherNet/IP ListIdentity", 98),
            ("firmware", f"{major}.{minor}", "EtherNet/IP ListIdentity", 98),
            ("serial", f"{serial:08X}", "EtherNet/IP ListIdentity", 98),
        ]
        if name:
            result.append(("model", name, "EtherNet/IP product name", 98))
        return result
    return []


def _bacnet_fingerprints(payload: bytes) -> list[tuple[str, str, str, int]]:
    if len(payload) < 12 or payload[0] != 0x81:
        return []
    marker = payload.find(b"\x10\x00\xc4", 4, min(len(payload), 48))
    if marker < 0 or marker + 7 > len(payload):
        return []
    object_id = struct.unpack("!I", payload[marker + 3:marker + 7])[0]
    if object_id >> 22 != 8:
        return []
    return [("role", "BACnet device", "BACnet I-Am", 95), ("bacnet_device_instance", str(object_id & 0x3FFFFF), "BACnet I-Am", 98)]


# --------------------------------------------------------------------------- DNP3
_DNP3_CRC_TABLE = []
for _byte in range(256):
    _crc = _byte
    for _ in range(8):
        _crc = (_crc >> 1) ^ 0xA6BC if _crc & 1 else _crc >> 1
    _DNP3_CRC_TABLE.append(_crc)


def _dnp3_crc(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc = (crc >> 8) ^ _DNP3_CRC_TABLE[(crc ^ byte) & 0xFF]
    return (~crc) & 0xFFFF


_DNP3_APP_FUNCTIONS = {
    0x00: "Confirm", 0x01: "Read", 0x02: "Write", 0x03: "Select", 0x04: "Operate", 0x05: "Direct operate",
    0x0D: "Cold restart", 0x0E: "Warm restart", 0x14: "Enable unsolicited", 0x15: "Disable unsolicited",
    0x81: "Response", 0x82: "Unsolicited response", 0x83: "Authentication response",
}


def _dnp3_fingerprints(payload: bytes) -> list[tuple[str, str, str, int]]:
    """DNP3 link-layer header (IEEE 1815). Validates the header CRC so port 20000 traffic
    that is not DNP3 does not produce false identity claims."""
    if len(payload) < 10 or payload[0:2] != b"\x05\x64":
        return []
    if struct.unpack("<H", payload[8:10])[0] != _dnp3_crc(payload[0:8]):
        return []
    control = payload[3]
    direction_master = bool(control & 0x80)
    destination, source = struct.unpack("<HH", payload[4:8])
    role = "DNP3 master" if direction_master else "DNP3 outstation"
    result = [("role", role, "DNP3 link-layer DIR bit", 90),
              ("dnp3_link_address", str(source), "DNP3 link-layer source address", 98),
              ("dnp3_peer_address", str(destination), "DNP3 link-layer destination address", 90)]
    # Application layer: first user-data block follows the header; transport header is one byte.
    if len(payload) >= 13:
        transport = payload[10]
        if transport & 0x40:  # FIR: application header present in this fragment
            function = payload[12]
            name = _DNP3_APP_FUNCTIONS.get(function, f"Function 0x{function:02X}")
            result.append(("dnp3_function", name, "DNP3 application header", 85))
            if function in (0x81, 0x82) and len(payload) >= 15:
                iin1, iin2 = payload[13], payload[14]
                flags = []
                if iin1 & 0x80: flags.append("device restart")
                if iin1 & 0x40: flags.append("device trouble")
                if iin1 & 0x20: flags.append("local control")
                if iin1 & 0x10: flags.append("need time")
                if iin2 & 0x08: flags.append("event buffer overflow")
                if iin2 & 0x04: flags.append("parameter error")
                if flags:
                    result.append(("dnp3_iin", ", ".join(flags), "DNP3 internal indications", 85))
    return result


# --------------------------------------------------------------------------- Siemens S7comm
_S7_TSAP_TYPES = {0x01: "PG (programming device)", 0x02: "OP (operator panel/HMI)", 0x03: "S7 basic communication"}
_S7_SZL_001C_FIELDS = {1: "plc_name", 2: "module_name", 3: "plant_identification", 4: "copyright", 5: "serial",
                       7: "module_type", 8: "memory_card_serial", 9: "manufacturer_id", 10: "profile", 11: "oem_id", 12: "location"}


def _s7_fingerprints(payload: bytes) -> list[tuple[str, str, str, int]]:
    """ISO-on-TCP (TPKT/COTP) carrying S7comm. Extracts connection TSAPs and, when a CPU
    answers a Read SZL request, the order number (MLFB), firmware version and CPU/component
    identification (SZL 0x0011 and 0x001C)."""
    if len(payload) < 7 or payload[0] != 0x03 or payload[1] != 0x00:
        return []
    cotp_len, pdu_type = payload[4], payload[5]
    result: list[tuple[str, str, str, int]] = []
    if pdu_type in (0xE0, 0xD0):  # connection request / confirm
        offset, end = 11, 5 + cotp_len
        role_hint = ""
        while offset + 2 <= min(end, len(payload)):
            code, size = payload[offset], payload[offset + 1]
            value = payload[offset + 2:offset + 2 + size]
            offset += 2 + size
            if code in (0xC1, 0xC2) and len(value) == 2:
                which = "src" if code == 0xC1 else "dst"
                kind, rack_slot = value[0], value[1]
                rack, slot = rack_slot >> 5, rack_slot & 0x1F
                label = f"{_S7_TSAP_TYPES.get(kind, f'type 0x{kind:02X}')}, rack {rack} slot {slot}"
                result.append((f"s7_{which}_tsap", label, "COTP connection TSAP", 85))
                if pdu_type == 0xD0 and which == "src":
                    role_hint = label
        if pdu_type == 0xD0:
            result.insert(0, ("role", "Siemens S7 controller", "COTP connection confirm on port 102", 85))
        elif pdu_type == 0xE0:
            result.insert(0, ("role", "S7 client (engineering/HMI/SCADA)", "COTP connection request on port 102", 70))
        return result
    if pdu_type != 0xF0:
        return []
    s7 = payload[7:]
    if len(s7) < 10 or s7[0] != 0x32:
        return []
    rosctr = s7[1]
    param_len, data_len = struct.unpack("!HH", s7[6:10])
    header_len = 10 if rosctr in (1, 7) else 12
    if rosctr in (2, 3):
        result.append(("role", "Siemens S7 controller", "S7comm acknowledgement from CPU", 90))
    if rosctr != 7:
        return result
    params = s7[header_len:header_len + param_len]
    data = s7[header_len + param_len:header_len + param_len + data_len]
    if len(params) < 8 or params[0:3] != b"\x00\x01\x12":
        return result
    method, group, subfunction = params[4], params[5], params[6]
    if method != 0x12 or group & 0x0F != 0x04 or subfunction != 0x01 or len(data) < 12:
        return result  # only Read SZL responses carry identification
    if data[0] != 0xFF:
        return result
    szl_id, szl_index = struct.unpack("!HH", data[4:8])
    entry_len, count = struct.unpack("!HH", data[8:12])
    entries = data[12:]
    result.append(("role", "Siemens S7 controller", "S7comm Read SZL response", 95))
    if szl_id == 0x0011 and entry_len == 28:
        for i in range(min(count, 8)):
            entry = entries[i * 28:(i + 1) * 28]
            if len(entry) < 28:
                break
            index = struct.unpack("!H", entry[0:2])[0]
            mlfb = _clean_text(entry[2:22])
            ausbg, ausbe = struct.unpack("!HH", entry[24:28])
            if index == 0x0001 and mlfb:
                result.append(("model", mlfb, "S7 SZL 0x0011 module order number (MLFB)", 98))
            elif index == 0x0006 and mlfb:
                result.append(("hardware", mlfb, "S7 SZL 0x0011 basic hardware", 90))
            elif index == 0x0007:
                result.append(("firmware", f"V{ausbg & 0xFF}.{ausbe >> 8}.{ausbe & 0xFF}", "S7 SZL 0x0011 basic firmware (order-code convention)", 85))
    elif szl_id == 0x001C and entry_len == 34:
        for i in range(min(count, 12)):
            entry = entries[i * 34:(i + 1) * 34]
            if len(entry) < 34:
                break
            index = struct.unpack("!H", entry[0:2])[0]
            value = _clean_text(entry[2:34])
            if value and index in _S7_SZL_001C_FIELDS:
                result.append((_S7_SZL_001C_FIELDS[index], value, f"S7 SZL 0x001C component {index}", 95))
    return result


# --------------------------------------------------------------------------- Profinet DCP
_PN_DEVICE_ROLES = {0x01: "IO device", 0x02: "IO controller", 0x04: "IO multidevice", 0x08: "IO supervisor"}


def _profinet_dcp(payload: bytes) -> tuple[str, list[tuple[str, str, str, int]], str]:
    """PN-DCP (Identify/Hello/Get/Set). Returns (station name, fingerprints, device IP)."""
    if len(payload) < 12:
        return "", [], ""
    frame_id, service_id, service_type = struct.unpack("!HBB", payload[0:4])
    if frame_id not in (0xFEFC, 0xFEFD, 0xFEFE, 0xFEFF):
        return "", [], ""
    data_len = struct.unpack("!H", payload[10:12])[0]
    blocks = payload[12:12 + data_len]
    is_response = service_type & 0x01 == 1 or service_id == 0x06  # Hello is sent by the device
    if not is_response:
        role = "Profinet controller/supervisor" if service_id == 0x05 else ""
        return "", ([("role", role, "PN-DCP identify request", 60)] if role else []), ""
    name, ip = "", ""
    result: list[tuple[str, str, str, int]] = [("role", "Profinet device", f"PN-DCP service 0x{service_id:02X} response", 90)]
    offset = 0
    while offset + 4 <= len(blocks):
        option, suboption, block_len = struct.unpack("!BBH", blocks[offset:offset + 4])
        body = blocks[offset + 4:offset + 4 + block_len]
        offset += 4 + block_len + (block_len & 1)
        if len(body) < 2:
            continue
        value = body[2:]  # skip BlockInfo
        if option == 0x02 and suboption == 0x01:
            result.append(("model", _clean_text(value), "PN-DCP device vendor value", 95))
        elif option == 0x02 and suboption == 0x02:
            name = _clean_text(value)
            result.append(("station_name", name, "PN-DCP name of station", 98))
        elif option == 0x02 and suboption == 0x03 and len(value) >= 4:
            vendor_id, device_id = struct.unpack("!HH", value[0:4])
            result.append(("profinet_vendor_id", f"0x{vendor_id:04X}", "PN-DCP device ID", 98))
            result.append(("profinet_device_id", f"0x{device_id:04X}", "PN-DCP device ID", 98))
            if vendor_id == 0x002A:
                result.append(("manufacturer", "Siemens AG", "PN-DCP vendor ID 0x002A", 95))
        elif option == 0x02 and suboption == 0x04 and value:
            roles = [label for bit, label in _PN_DEVICE_ROLES.items() if value[0] & bit]
            if roles:
                result[0] = ("role", "Profinet " + " / ".join(roles), "PN-DCP device role", 95)
        elif option == 0x01 and suboption == 0x02 and len(value) >= 12:
            ip = socket.inet_ntoa(value[0:4])
            result.append(("profinet_ip", f"{ip}/{socket.inet_ntoa(value[4:8])} gw {socket.inet_ntoa(value[8:12])}", "PN-DCP IP parameter", 95))
    return name, result, ip


def parse_ethernet(frame: bytes, timestamp: float) -> PacketObservation | None:
    if len(frame) < 14:
        return None
    dst_mac, src_mac = _mac(frame[0:6]), _mac(frame[6:12])
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    vlan = None
    while ethertype in (0x8100, 0x88A8, 0x9100) and len(frame) >= offset + 4:
        tci, ethertype = struct.unpack("!HH", frame[offset:offset + 4])
        vlan = tci & 0x0FFF
        offset += 4

    obs = PacketObservation(timestamp, len(frame), src_mac, dst_mac, ethertype, vlan)

    if ethertype == 0x0806 and len(frame) >= offset + 28:
        htype, ptype, hlen, plen, _oper = struct.unpack("!HHBBH", frame[offset:offset + 8])
        if htype == 1 and ptype == 0x0800 and hlen == 6 and plen == 4:
            obs.src_mac = _mac(frame[offset + 8:offset + 14])
            obs.src_ip = socket.inet_ntoa(frame[offset + 14:offset + 18])
            target_mac = _mac(frame[offset + 18:offset + 24])
            target_ip = socket.inet_ntoa(frame[offset + 24:offset + 28])
            obs.dst_mac = target_mac if _is_unicast_mac(target_mac) else dst_mac
            obs.dst_ip = target_ip
            obs.transport = "ARP"
            obs.app_protocol = "ARP"
        return obs

    payload_offset = offset
    if ethertype == 0x0800 and len(frame) >= offset + 20:
        version_ihl = frame[offset]
        if version_ihl >> 4 != 4:
            return obs
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(frame) < offset + ihl:
            return obs
        proto = frame[offset + 9]
        obs.src_ip = socket.inet_ntoa(frame[offset + 12:offset + 16])
        obs.dst_ip = socket.inet_ntoa(frame[offset + 16:offset + 20])
        payload_offset = offset + ihl
    elif ethertype == 0x86DD and len(frame) >= offset + 40:
        if frame[offset] >> 4 != 6:
            return obs
        proto = frame[offset + 6]
        obs.src_ip = socket.inet_ntop(socket.AF_INET6, frame[offset + 8:offset + 24])
        obs.dst_ip = socket.inet_ntop(socket.AF_INET6, frame[offset + 24:offset + 40])
        payload_offset = offset + 40
    else:
        obs.transport = {0x88CC: "LLDP", 0x888E: "802.1X", 0x8809: "LACP", 0x8892: "PROFINET"}.get(ethertype, "OTHER")
        obs.app_protocol = obs.transport
        if obs.app_protocol == "LLDP":
            obs.fingerprints = _lldp_fingerprints(frame[offset:])
        elif obs.app_protocol == "PROFINET" and len(frame) >= offset + 2:
            frame_id = struct.unpack("!H", frame[offset:offset + 2])[0]
            if 0xFEFC <= frame_id <= 0xFEFF:
                obs.app_protocol = "PROFINET-DCP"
                obs.source_name, obs.fingerprints, obs.src_ip = _profinet_dcp(frame[offset:])
                obs.dst_ip = ""
            elif 0x8000 <= frame_id <= 0xBFFF:
                obs.app_protocol = "PROFINET-RT"
            elif 0xFC00 <= frame_id <= 0xFCFF:
                obs.app_protocol = "PROFINET-ALARM"
            elif 0xFF00 <= frame_id <= 0xFF43:
                obs.app_protocol = "PROFINET-PTCP"
        return obs

    app_payload = frame[payload_offset:]
    if proto == 6 and len(app_payload) >= 20:
        obs.transport = "TCP"
        obs.src_port, obs.dst_port = struct.unpack("!HH", app_payload[:4])
        tcp_hlen = (app_payload[12] >> 4) * 4
        app_payload = app_payload[tcp_hlen:] if tcp_hlen >= 20 else b""
    elif proto == 17 and len(app_payload) >= 8:
        obs.transport = "UDP"
        obs.src_port, obs.dst_port = struct.unpack("!HH", app_payload[:4])
        app_payload = app_payload[8:]
    elif proto == 1:
        obs.transport = "ICMP"
    elif proto == 58:
        obs.transport = "ICMPV6"
    else:
        obs.transport = f"IP-{proto}"

    obs.app_protocol = _app_protocol(obs.src_port, obs.dst_port, obs.transport)
    if obs.app_protocol == "DHCP":
        obs.source_name, obs.fingerprints = _dhcp_details(app_payload)
    if obs.app_protocol in ("DNS", "MDNS", "LLMNR"):
        obs.name_claims = _dns_claims(app_payload)
    if obs.app_protocol == "HTTP":
        obs.fingerprints.extend(_http_fingerprints(app_payload))
    elif obs.app_protocol == "MODBUS-TCP":
        obs.fingerprints.extend(_modbus_fingerprints(app_payload))
    elif obs.app_protocol == "ETHERNET-IP":
        obs.fingerprints.extend(_enip_fingerprints(app_payload))
    elif obs.app_protocol == "BACNET-IP":
        obs.fingerprints.extend(_bacnet_fingerprints(app_payload))
    elif obs.app_protocol == "DNP3":
        obs.fingerprints.extend(_dnp3_fingerprints(app_payload))
    elif obs.app_protocol == "S7COMM":
        obs.fingerprints.extend(_s7_fingerprints(app_payload))
    return obs


def endpoint_candidates(obs: PacketObservation) -> list[tuple[str, str, str]]:
    """Return (mac, ip, name) endpoints that are defensible from this frame."""
    result: list[tuple[str, str, str]] = []
    if _is_unicast_mac(obs.src_mac):
        result.append((obs.src_mac, obs.src_ip if _is_endpoint_ip(obs.src_ip) else "", obs.source_name))
    if _is_unicast_mac(obs.dst_mac) and _is_endpoint_ip(obs.dst_ip):
        result.append((obs.dst_mac, obs.dst_ip, ""))
    for ip, name in obs.name_claims:
        if _is_endpoint_ip(ip):
            result.append(("", ip, name))
    return result
