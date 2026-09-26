"""Passive OPC UA (binary transport) decoder.

Reads what the two sides of an OPC UA connection tell each other in the clear:

* Hello — the client names the server's endpoint URL.
* OpenSecureChannel — the security policy, and the sender's X.509 certificate subject.
* CreateSession / GetEndpoints / FindServers — application names, product URIs, endpoint
  descriptions (security mode, policy, accepted user-token types).
* ActivateSession — how the client authenticated (anonymous, user name, certificate, token).

Message bodies are only readable when the channel's security mode is None or Sign (Sign leaves
the body in the clear, with a signature appended); under SignAndEncrypt only Hello and
OpenSecureChannel are visible. No connection state is kept: every message is checked for a
known type id and sane string lengths before anything is believed.

Fingerprints are returned as two lists — claims about the SENDER of the frame and claims about
the RECEIVER (a Hello says something about the server it is addressed to).
"""
from __future__ import annotations

import ipaddress
import re
import struct
from urllib.parse import urlparse

Fingerprint = tuple[str, str, str, int]

MESSAGE_TYPES = {b"HEL", b"ACK", b"ERR", b"RHE", b"OPN", b"CLO", b"MSG"}

# NodeId numeric ids (namespace 0) of the service messages we understand
CREATE_SESSION_REQ, CREATE_SESSION_RSP = 461, 464
GET_ENDPOINTS_REQ, GET_ENDPOINTS_RSP = 428, 431
FIND_SERVERS_REQ, FIND_SERVERS_RSP = 422, 425
ACTIVATE_SESSION_REQ = 467
OPEN_CHANNEL_REQ, OPEN_CHANNEL_RSP = 446, 449
IDENTITY_TOKENS = {321: "Anonymous", 324: "User name", 327: "X.509 certificate", 940: "Issued token"}
SECURITY_MODES = {1: "None", 2: "Sign", 3: "SignAndEncrypt"}
APPLICATION_TYPES = {0: "Server", 1: "Client", 2: "Client and server", 3: "Discovery server"}

# Product URI / application name → (vendor, is-controller-vendor). Controller vendors become the
# asset's manufacturer claim (the OPC UA server runs inside the PLC); software vendors do not.
VENDOR_HINTS = [
    ("siemens", "Siemens", True), ("simatic", "Siemens", True), ("rockwell", "Rockwell Automation", True),
    ("allen-bradley", "Rockwell Automation", True), ("beckhoff", "Beckhoff", True), ("br-automation", "B&R", True),
    ("wago", "WAGO", True), ("phoenixcontact", "Phoenix Contact", True), ("phoenix contact", "Phoenix Contact", True),
    ("schneider", "Schneider Electric", True), ("omron", "Omron", True), ("bosch", "Bosch Rexroth", True),
    ("mitsubishi", "Mitsubishi Electric", True), ("abb", "ABB", True), ("honeywell", "Honeywell", False),
    ("emerson", "Emerson", False), ("kepware", "PTC Kepware", False), ("ptc", "PTC Kepware", False),
    ("inductiveautomation", "Inductive Automation (Ignition)", False), ("ignition", "Inductive Automation (Ignition)", False),
    ("prosys", "Prosys OPC", False), ("unifiedautomation", "Unified Automation", False), ("softing", "Softing", False),
    ("matrikon", "Matrikon", False), ("aveva", "AVEVA", False), ("wonderware", "AVEVA", False), ("ge-ip", "GE", False),
    ("open62541", "open62541 (open source)", False), ("node-opcua", "node-opcua (open source)", False),
    ("freeopcua", "FreeOpcUa (open source)", False), ("opcfoundation", "OPC Foundation sample", False),
]


class UaReader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data, self.pos = data, pos

    def _take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int: return self._take(1)[0]
    def u16(self) -> int: return struct.unpack("<H", self._take(2))[0]
    def u32(self) -> int: return struct.unpack("<I", self._take(4))[0]
    def i32(self) -> int: return struct.unpack("<i", self._take(4))[0]
    def i64(self) -> int: return struct.unpack("<q", self._take(8))[0]
    def f64(self) -> float: return struct.unpack("<d", self._take(8))[0]

    def bytestring(self, limit: int = 65536) -> bytes | None:
        n = self.i32()
        if n == -1:
            return None
        if n < 0 or n > limit:
            raise ValueError("bad length")
        return self._take(n)

    def string(self, limit: int = 4096) -> str:
        raw = self.bytestring(limit)
        if raw is None:
            return ""
        text = raw.decode("utf-8")  # raises on encrypted garbage — that is the point
        if any(ord(c) < 32 and c not in "\t\r\n" for c in text):
            raise ValueError("control characters in string")
        return text.strip()

    def localized_text(self) -> str:
        mask = self.u8()
        if mask & ~0x03:
            raise ValueError("bad LocalizedText mask")
        locale = self.string() if mask & 0x01 else ""
        text = self.string() if mask & 0x02 else ""
        return text or locale

    def nodeid(self) -> tuple[int, object]:
        enc = self.u8()
        kind = enc & 0x0F
        if kind == 0:
            ns, ident = 0, self.u8()
        elif kind == 1:
            ns, ident = self.u8(), self.u16()
        elif kind == 2:
            ns, ident = self.u16(), self.u32()
        elif kind == 3:
            ns, ident = self.u16(), self.string()
        elif kind == 4:
            ns, ident = self.u16(), self._take(16).hex()
        elif kind == 5:
            ns, ident = self.u16(), (self.bytestring() or b"").hex()
        else:
            raise ValueError("bad NodeId encoding")
        if enc & 0x80:
            self.string()  # namespace uri
        if enc & 0x40:
            self.u32()  # server index
        return ns, ident

    def extension_object(self) -> tuple[tuple[int, object], bytes | None]:
        node = self.nodeid()
        enc = self.u8()
        if enc == 0:
            return node, None
        if enc in (1, 2):
            return node, self.bytestring()
        raise ValueError("bad ExtensionObject encoding")

    def diagnostic_info(self, depth: int = 0) -> None:
        mask = self.u8()
        if mask & ~0x7F or depth > 4:
            raise ValueError("bad DiagnosticInfo")
        if mask & 0x01: self.i32()
        if mask & 0x02: self.i32()
        if mask & 0x04: self.i32()
        if mask & 0x08: self.i32()
        if mask & 0x10: self.string()
        if mask & 0x20: self.u32()
        if mask & 0x40: self.diagnostic_info(depth + 1)

    def array(self, item, limit: int = 256) -> list:
        n = self.i32()
        if n == -1:
            return []
        if n < 0 or n > limit:
            raise ValueError("bad array length")
        return [item() for _ in range(n)]

    def request_header(self) -> None:
        self.nodeid(); self.i64(); self.u32(); self.u32(); self.string(); self.u32(); self.extension_object()

    def response_header(self) -> int:
        self.i64(); self.u32(); result = self.u32(); self.diagnostic_info(); self.array(self.string); self.extension_object()
        return result

    def application_description(self) -> dict:
        d = {"uri": self.string(), "product": self.string(), "name": self.localized_text(), "type": self.u32()}
        self.string(); self.string()
        d["discovery"] = self.array(self.string, 32)
        if d["type"] > 3:
            raise ValueError("bad ApplicationType")
        return d

    def endpoint_description(self) -> dict:
        d = {"url": self.string(), "server": self.application_description()}
        self.bytestring(1 << 20)  # server certificate
        d["mode"] = self.u32(); d["policy"] = self.string()
        def token_policy():
            self.string(); t = self.u32(); self.string(); self.string(); self.string()
            return t
        d["tokens"] = self.array(token_policy, 32)
        self.string(); self.u8()
        if d["mode"] not in SECURITY_MODES:
            raise ValueError("bad MessageSecurityMode")
        return d


def _policy_name(uri: str) -> str:
    return uri.rsplit("#", 1)[-1] if "#" in uri else uri


def _certificate_subject_cn(der: bytes | None) -> str:
    """Common name from a DER certificate: the printable string following OID 2.5.4.3 (id-at-commonName)."""
    if not der:
        return ""
    idx = der.find(b"\x06\x03\x55\x04\x03")
    if idx < 0:
        return ""
    pos = idx + 5
    if pos + 2 > len(der):
        return ""
    tag, length = der[pos], der[pos + 1]
    if tag not in (0x0C, 0x13, 0x16, 0x1E) or length & 0x80:
        return ""
    raw = der[pos + 2:pos + 2 + length]
    try:
        text = raw.decode("utf-16-be") if tag == 0x1E else raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    return re.sub(r"\s+", " ", text).strip()[:120]


def _vendor_hint(*texts: str) -> tuple[str, bool] | None:
    blob = " ".join(t.lower() for t in texts if t)
    for needle, vendor, controller in VENDOR_HINTS:
        if needle in blob:
            return vendor, controller
    return None


def _url_host(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return ""
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""  # an address, not a name
    except ValueError:
        return host


def _application_claims(app: dict, evidence: str, confidence: int) -> list[Fingerprint]:
    out: list[Fingerprint] = []
    if app.get("name"):
        out.append(("opcua_application", app["name"][:200], evidence, confidence))
    if app.get("uri"):
        out.append(("opcua_application_uri", app["uri"][:200], evidence, confidence))
    if app.get("product"):
        out.append(("opcua_product", app["product"][:200], evidence, confidence))
    hint = _vendor_hint(app.get("product", ""), app.get("name", ""), app.get("uri", ""))
    if hint:
        vendor, controller = hint
        out.append(("manufacturer" if controller else "software", vendor, evidence, 80 if controller else confidence))
    return out


def decode(payload: bytes) -> tuple[list[Fingerprint], list[Fingerprint], list[tuple[str, str]]] | None:
    """Decode one OPC UA TCP message. Returns (sender claims, receiver claims, (host, name) claims)
    or None when the payload is not OPC UA."""
    if len(payload) < 8 or payload[:3] not in MESSAGE_TYPES or payload[3:4] not in (b"F", b"C", b"A"):
        return None
    size = struct.unpack("<I", payload[4:8])[0]
    if size < 8 or size > (16 << 20):
        return None
    kind = payload[:3]
    src: list[Fingerprint] = []
    dst: list[Fingerprint] = []
    names: list[tuple[str, str]] = []
    r = UaReader(payload, 8)
    try:
        if kind == b"HEL":
            r.u32(); r.u32(); r.u32(); r.u32(); r.u32()
            url = r.string(512)
            src.append(("role", "OPC UA client", "OPC UA Hello", 85))
            dst.append(("role", "OPC UA server", "OPC UA Hello", 85))
            if url:
                dst.append(("opcua_endpoint", url[:200], "OPC UA Hello (client-supplied endpoint URL)", 80))
                host = _url_host(url)
                if host:
                    names.append((host, "OPC UA endpoint URL"))
        elif kind == b"ACK":
            src.append(("role", "OPC UA server", "OPC UA Acknowledge", 85))
        elif kind == b"OPN":
            r.u32()
            policy = r.string(256)
            cert = r.bytestring(1 << 20)
            r.bytestring(64)
            if policy:
                src.append(("opcua_security_policy", _policy_name(policy), "OPC UA OpenSecureChannel", 90))
            cn = _certificate_subject_cn(cert)
            if cn:
                src.append(("opcua_certificate_cn", cn, "OPC UA OpenSecureChannel sender certificate", 90))
            # body is plaintext only with SecurityPolicy#None; try, and fall through quietly if not
            try:
                r.u32(); r.u32()
                ns, ident = r.nodeid()
                if ns == 0 and ident == OPEN_CHANNEL_REQ:
                    src.append(("role", "OPC UA client", "OPC UA OpenSecureChannel request", 85))
                elif ns == 0 and ident == OPEN_CHANNEL_RSP:
                    src.append(("role", "OPC UA server", "OPC UA OpenSecureChannel response", 85))
            except ValueError:
                pass
        elif kind == b"MSG":
            r.u32(); r.u32(); r.u32(); r.u32()
            ns, ident = r.nodeid()
            if ns != 0 or not isinstance(ident, int):
                return src, dst, names
            if ident == CREATE_SESSION_REQ:
                r.request_header()
                client = r.application_description()
                server_uri = r.string(); endpoint = r.string(512); session = r.string()
                src.append(("role", "OPC UA client", "OPC UA CreateSession request", 95))
                src.extend(_application_claims(client, "OPC UA CreateSession client description", 90))
                dst.append(("role", "OPC UA server", "OPC UA CreateSession request", 90))
                if endpoint:
                    dst.append(("opcua_endpoint", endpoint[:200], "OPC UA CreateSession request", 85))
                    host = _url_host(endpoint)
                    if host:
                        names.append((host, "OPC UA endpoint URL"))
                if server_uri:
                    dst.append(("opcua_application_uri", server_uri[:200], "OPC UA CreateSession request (server URI)", 80))
                if session:
                    src.append(("opcua_session_name", session[:120], "OPC UA CreateSession request", 80))
            elif ident == CREATE_SESSION_RSP:
                if r.response_header() != 0:
                    return src, dst, names
                r.nodeid(); r.nodeid(); r.f64(); r.bytestring(4096); r.bytestring(1 << 20)
                endpoints = r.array(r.endpoint_description, 64)
                src.append(("role", "OPC UA server", "OPC UA CreateSession response", 95))
                src.extend(_endpoint_claims(endpoints, "OPC UA CreateSession response"))
            elif ident == GET_ENDPOINTS_RSP:
                if r.response_header() != 0:
                    return src, dst, names
                endpoints = r.array(r.endpoint_description, 64)
                src.append(("role", "OPC UA server", "OPC UA GetEndpoints response", 95))
                src.extend(_endpoint_claims(endpoints, "OPC UA GetEndpoints response"))
            elif ident == GET_ENDPOINTS_REQ:
                r.request_header()
                endpoint = r.string(512)
                src.append(("role", "OPC UA client", "OPC UA GetEndpoints request", 90))
                dst.append(("role", "OPC UA server", "OPC UA GetEndpoints request", 85))
                if endpoint:
                    dst.append(("opcua_endpoint", endpoint[:200], "OPC UA GetEndpoints request", 80))
            elif ident == FIND_SERVERS_RSP:
                if r.response_header() != 0:
                    return src, dst, names
                servers = r.array(r.application_description, 64)
                src.append(("role", "OPC UA server", "OPC UA FindServers response", 90))
                for app in servers[:8]:
                    src.extend(_application_claims(app, "OPC UA FindServers response", 85))
            elif ident == ACTIVATE_SESSION_REQ:
                r.request_header()
                r.string(); r.bytestring(4096)  # client signature
                r.array(lambda: (r.bytestring(1 << 20), r.bytestring(4096)), 32)  # software certificates
                r.array(r.string, 32)  # locale ids
                (tns, tid), body = r.extension_object()
                label = IDENTITY_TOKENS.get(tid if tns == 0 and isinstance(tid, int) else -1, "")
                src.append(("role", "OPC UA client", "OPC UA ActivateSession request", 90))
                if label:
                    detail = label
                    if tid == 324 and body:
                        b = UaReader(body)
                        b.string()  # policy id
                        user = b.string(256)
                        if user:
                            detail = f"User name ({user})"
                    src.append(("opcua_auth", detail, "OPC UA ActivateSession request", 90))
    except (ValueError, struct.error, UnicodeDecodeError):
        # Encrypted body, a chunk we don't have, or not the message we thought: keep whatever was
        # collected before the failure — those fields were validated as they were read.
        pass
    return src, dst, names


def _endpoint_claims(endpoints: list[dict], evidence: str) -> list[Fingerprint]:
    out: list[Fingerprint] = []
    if not endpoints:
        return out
    server = endpoints[0]["server"]
    out.extend(_application_claims(server, evidence, 95))
    modes = sorted({SECURITY_MODES[e["mode"]] for e in endpoints})
    policies = sorted({_policy_name(e["policy"]) for e in endpoints if e["policy"]})
    tokens = sorted({{0: "Anonymous", 1: "User name", 2: "Certificate", 3: "Issued token"}.get(t, str(t)) for e in endpoints for t in e["tokens"]})
    urls = sorted({e["url"] for e in endpoints if e["url"]})
    if urls:
        out.append(("opcua_endpoint", urls[0][:200], evidence, 95))
    if modes:
        out.append(("opcua_security_modes", ", ".join(modes), evidence, 95))
    if policies:
        out.append(("opcua_security_policies", ", ".join(policies)[:200], evidence, 95))
    if tokens:
        out.append(("opcua_user_tokens", ", ".join(tokens), evidence, 95))
    return out
