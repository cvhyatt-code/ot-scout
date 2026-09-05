"""Passive EtherNet/IP explicit messaging (CIP) decoder.

ListIdentity (UDP/TCP broadcast, already decoded in parser.py) is what a device says when asked
"who's there". Explicit messaging is what an HMI or engineering tool actually asks a specific
device — and a Get_Attributes_All / Get_Attribute_Single on the Identity object (class 0x01)
returns vendor, device type, product code, firmware revision, serial number and product name.

Requests and responses have to be paired: a CIP response does not name the object it came from.
The encapsulation header's 8-byte "sender context" is echoed back by the target, so requests are
remembered by (client, server, context) in a small bounded table and matched when the reply
arrives. Only unconnected messaging (SendRRData, with or without an Unconnected_Send wrapper via
the Connection Manager) is paired; connected class-3 messaging keys on connection ids that differ
per direction and is left alone.
"""
from __future__ import annotations

import struct

Fingerprint = tuple[str, str, str, int]

SEND_RR_DATA = 0x6F
IDENTITY_CLASS = 0x01
CONNECTION_MANAGER_CLASS = 0x06
GET_ATTRIBUTES_ALL = 0x01
GET_ATTRIBUTE_SINGLE = 0x0E
UNCONNECTED_SEND = 0x52

# CIP vendor ids (ODVA-assigned). Only ids that are unambiguous; anything else is reported by number.
VENDORS = {
    1: "Rockwell Automation / Allen-Bradley", 7: "SMC Corporation", 8: "Molex", 26: "Festo",
    44: "Yaskawa", 47: "Omron", 48: "Turck", 90: "HMS Industrial Networks", 243: "Schneider Electric",
    283: "Endress+Hauser", 588: "Siemens", 668: "Phoenix Contact",
}

DEVICE_TYPES = {
    0x02: ("AC Drive", "Drive"), 0x03: ("Motor Overload", "Drive"), 0x07: ("General Purpose Discrete I/O", "I/O adapter"),
    0x0C: ("Communications Adapter", "Communications adapter"), 0x0E: ("Programmable Logic Controller", "PLC (EtherNet/IP)"),
    0x10: ("Position Controller", "Motion controller"), 0x13: ("DC Drive", "Drive"), 0x1A: ("Safety Discrete I/O Device", "Safety I/O"),
    0x22: ("Pneumatic Valve(s)", "Pneumatic valve terminal"), 0x25: ("CIP Motion Drive", "Drive"), 0x2B: ("Human-Machine Interface", "HMI"),
    0x2C: ("Managed Ethernet Switch", "Network infrastructure"),
}

_PENDING: dict[tuple, tuple] = {}
_PENDING_MAX = 512


def _remember(key: tuple, value: tuple) -> None:
    if len(_PENDING) >= _PENDING_MAX:
        del _PENDING[next(iter(_PENDING))]
    _PENDING[key] = value


def _epath(data: bytes, words: int) -> tuple[dict, int]:
    """Decode a padded EPATH of `words` 16-bit words → {class, instance, attribute}, bytes consumed."""
    path: dict[str, int] = {}
    pos, end = 0, words * 2
    while pos < end and pos < len(data):
        seg = data[pos]
        if seg in (0x20, 0x24, 0x28, 0x30):  # 8-bit class / instance / member / attribute
            if pos + 2 > len(data): break
            path[{0x20: "class", 0x24: "instance", 0x28: "member", 0x30: "attribute"}[seg]] = data[pos + 1]
            pos += 2
        elif seg in (0x21, 0x25, 0x29, 0x31):  # 16-bit forms, padded
            if pos + 4 > len(data): break
            path[{0x21: "class", 0x25: "instance", 0x29: "member", 0x31: "attribute"}[seg]] = struct.unpack("<H", data[pos + 2:pos + 4])[0]
            pos += 4
        elif seg == 0x22 or seg == 0x26:  # 32-bit class / instance
            if pos + 6 > len(data): break
            path["class" if seg == 0x22 else "instance"] = struct.unpack("<I", data[pos + 2:pos + 6])[0]
            pos += 6
        elif seg & 0xE0 == 0x00:  # port segment (routing) — skip
            extended = seg & 0x10
            if extended:
                if pos + 2 > len(data): break
                n = data[pos + 1]; pos += 2 + n + (n & 1)
            else:
                pos += 2
        elif seg & 0xE0 == 0x80:  # data segment (ANSI symbol etc.) — skip
            if pos + 2 > len(data): break
            n = data[pos + 1]; pos += 2 + n + (n & 1)
        else:
            break
    return path, end


def _cpf_items(data: bytes) -> list[tuple[int, bytes]]:
    if len(data) < 2:
        return []
    count = struct.unpack("<H", data[:2])[0]
    pos, items = 2, []
    for _ in range(min(count, 8)):
        if pos + 4 > len(data):
            break
        item_type, size = struct.unpack("<HH", data[pos:pos + 4])
        items.append((item_type, data[pos + 4:pos + 4 + size]))
        pos += 4 + size
    return items


def _request_target(cip: bytes) -> tuple[int, dict] | None:
    """(service, path) of a CIP request, unwrapping an Unconnected_Send to its embedded request."""
    if len(cip) < 2:
        return None
    service, words = cip[0], cip[1]
    if service & 0x80:
        return None
    path, used = _epath(cip[2:], words)
    if service == UNCONNECTED_SEND and path.get("class") == CONNECTION_MANAGER_CLASS:
        body = cip[2 + used:]
        if len(body) < 4:
            return None
        size = struct.unpack("<H", body[2:4])[0]
        return _request_target(body[4:4 + size])
    return service, path


def _identity_fingerprints(vendor_id: int, device_type: int, product_code: int, major: int, minor: int,
                           serial: int, name: str, evidence: str) -> list[Fingerprint]:
    out: list[Fingerprint] = [
        ("vendor_id", str(vendor_id), evidence, 98),
        ("device_type", str(device_type), evidence, 98),
        ("product_code", str(product_code), evidence, 98),
        ("firmware", f"{major}.{minor:03d}", evidence, 98),
        ("serial", f"{serial:08X}", evidence, 98),
    ]
    if vendor_id in VENDORS:
        out.append(("manufacturer", VENDORS[vendor_id], evidence, 95))
    kind = DEVICE_TYPES.get(device_type)
    out.append(("role", kind[1] if kind else "EtherNet/IP device", evidence, 95))
    if kind:
        out.append(("cip_device_type", kind[0], evidence, 98))
    if name:
        out.append(("model", name, evidence.replace("Identity object", "product name"), 98))
    return out


def _short_string(data: bytes) -> str:
    if not data:
        return ""
    n = data[0]
    return data[1:1 + n].decode("utf-8", "replace").strip()


def decode(payload: bytes, src_ip: str, src_port: int | None, dst_ip: str, dst_port: int | None) -> list[Fingerprint]:
    """Fingerprints about the SENDER of this encapsulation packet (the device answering an identity read)."""
    if len(payload) < 24:
        return []
    command, length, _session, status = struct.unpack("<HHII", payload[:12])
    context = payload[12:20]
    if command != SEND_RR_DATA or status != 0 or len(payload) < 24 + 6:
        return []
    data = payload[24:24 + length]
    if len(data) < 6:
        return []
    items = _cpf_items(data[6:])  # after interface handle + timeout
    cip = next((body for t, body in items if t == 0x00B2), None)
    if cip is None or len(cip) < 2:
        return []
    if not cip[0] & 0x80:
        target = _request_target(cip)
        if target:
            _remember((src_ip, src_port, dst_ip, dst_port, context), target)
            if target[1].get("class") == IDENTITY_CLASS:
                return [("role", "EtherNet/IP client (HMI/engineering)", "EtherNet/IP Identity object read", 70)]
        return []
    # response: pair with the request the other side sent us
    pending = _PENDING.pop((dst_ip, dst_port, src_ip, src_port, context), None)
    if not pending:
        return []
    service, path = pending
    if path.get("class") != IDENTITY_CLASS or len(cip) < 4:
        return []
    reply_service, general_status, extra_words = cip[0] & 0x7F, cip[2], cip[3]
    if reply_service != service or general_status != 0:
        return []
    body = cip[4 + extra_words * 2:]
    evidence = "EtherNet/IP Identity object"
    if service == GET_ATTRIBUTES_ALL and len(body) >= 14:
        vendor_id, device_type, product_code = struct.unpack("<HHH", body[:6])
        major, minor = body[6], body[7]
        serial = struct.unpack("<I", body[10:14])[0]
        return _identity_fingerprints(vendor_id, device_type, product_code, major, minor, serial, _short_string(body[14:]), evidence)
    if service == GET_ATTRIBUTE_SINGLE:
        attribute = path.get("attribute")
        try:
            if attribute == 1 and len(body) >= 2:
                vid = struct.unpack("<H", body[:2])[0]
                out = [("vendor_id", str(vid), evidence, 98)]
                if vid in VENDORS:
                    out.append(("manufacturer", VENDORS[vid], evidence, 95))
                return out
            if attribute == 2 and len(body) >= 2:
                dt = struct.unpack("<H", body[:2])[0]
                kind = DEVICE_TYPES.get(dt)
                out = [("device_type", str(dt), evidence, 98), ("role", kind[1] if kind else "EtherNet/IP device", evidence, 95)]
                if kind:
                    out.append(("cip_device_type", kind[0], evidence, 98))
                return out
            if attribute == 3 and len(body) >= 2:
                return [("product_code", str(struct.unpack("<H", body[:2])[0]), evidence, 98)]
            if attribute == 4 and len(body) >= 2:
                return [("firmware", f"{body[0]}.{body[1]:03d}", evidence, 98)]
            if attribute == 6 and len(body) >= 4:
                return [("serial", f"{struct.unpack('<I', body[:4])[0]:08X}", evidence, 98)]
            if attribute == 7 and len(body) >= 1:
                name = _short_string(body)
                return [("model", name, "EtherNet/IP product name", 98)] if name else []
        except struct.error:
            return []
    return []
