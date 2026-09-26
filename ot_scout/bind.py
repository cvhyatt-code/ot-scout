"""Where the web interface may listen, and which requests it will answer.

Three checks stand between the interface and anyone who is not the assessor:

- **A per-launch token.** `run.py` makes a fresh random token every time it starts and prints it
  inside the URL it shows. Opening that URL sets a cookie; the page then sends the token in a header
  with every request that changes something. A request without it, or with last launch's, is refused.
- **Host.** A page on the internet can point a hostname it owns at 127.0.0.1 and have the assessor's
  own browser fetch from us (DNS rebinding). The name the browser typed survives only in the Host
  header, so an unexpected one is refused.
- **Origin.** A state-changing request that a page elsewhere talked the browser into making carries
  that page's Origin, and is refused.

The interface binds loopback by default. A non-loopback bind is allowed, with a warning: the token
still guards it, but it puts the interface on a network the assessor may be assessing.
"""
from __future__ import annotations

import hmac
import secrets
from urllib.parse import urlparse

LOOPBACK_NAMES = {"localhost", "::1", "0:0:0:0:0:0:0:1"}
WILDCARD_BINDS = {"", "0.0.0.0", "::", "[::]"}

# Names a browser may legitimately use to reach the interface on this machine. Chrome on a
# Chromebook reaches the Linux container through `localhost`.
LOOPBACK_HOST_HEADERS = frozenset({"127.0.0.1", "localhost", "[::1]", "::1"})

TOKEN_HEADER = "X-Scout-Token"

TUNNELS = """To reach a remote collector, forward the port over something that authenticates instead:
  ssh -L 8767:localhost:8767 user@collector     # then browse the URL it printed, on this machine

A port forward arrives as localhost and needs nothing further. A reverse proxy that keeps the name
the browser typed has to have that name allowed, or every request is refused with 421:
  python3 run.py --allowed-host collector.example.internal"""


def new_token() -> str:
    return secrets.token_urlsafe(24)


def token_ok(presented: str | None, expected: str | None) -> bool:
    """True if the request carries this launch's token. Compared in constant time."""
    if not expected or not presented:
        return False
    return hmac.compare_digest(presented.encode("utf-8", "replace"), expected.encode("utf-8"))


def cookie_name(port: int) -> str:
    """Cookies are not separated by port, so two instances on one machine need different names."""
    return f"scout_token_{int(port)}"


def is_loopback(host: str) -> bool:
    """True if binding this address keeps the interface on the machine itself."""
    value = (host or "").strip().lower()
    if not value:
        return False
    return value in LOOPBACK_NAMES or value.split("%")[0].startswith("127.")


def bare_host(value: str) -> str:
    """A Host header or hostname reduced to the name we compare on: lowercase, no port, no root dot.

    One function so the allowlist and the check can never disagree about what a name is. If they
    could drift, `--allowed-host name:8443` would be accepted at the command line and then silently
    never match, which is the worst way for a security control to fail.
    """
    name = (value or "").strip().lower().rstrip(".")
    if name.startswith("["):                       # [::1]:8767
        return name.partition("]")[0] + "]"
    if name.count(":") == 1:                       # host:port, but not a bare IPv6 literal
        return name.rsplit(":", 1)[0]
    return name


def allowed_hosts(host: str, extra=None) -> frozenset[str]:
    """Host header values this server will answer to.

    Always the loopback names. A specific non-loopback bind address adds itself. `extra` is how a name
    the tool cannot guess gets through — a reverse proxy that keeps the name the browser typed, or the
    machine's LAN name on a wildcard bind. Naming one is not the same as switching the check off:
    every other name is still refused, which is what stops a rebinding attack.
    """
    names = {bare_host(n) for n in (extra or ()) if (n or "").strip()}
    bound = (host or "").strip().lower()
    if bound not in WILDCARD_BINDS:
        names.add(f"[{bound}]" if ":" in bound and not bound.startswith("[") else bare_host(bound))
    return LOOPBACK_HOST_HEADERS | names


def host_header_ok(value: str | None, allowed: frozenset[str] | None) -> bool:
    """True if a request carrying this Host header may be answered."""
    if allowed is None:
        return True
    if not value:
        return False
    return bare_host(value) in allowed


def origin_ok(value: str | None, allowed: frozenset[str] | None) -> bool:
    """True if a state-changing request carrying this Origin may proceed.

    No Origin means no browser: curl, a script, the CLI. Those still need the token. An Origin that is
    present and foreign is a page somewhere else spending the assessor's access.
    """
    if allowed is None or value is None:
        return True
    if value == "null":                            # sandboxed iframe, data: document, file://
        return False
    return host_header_ok(urlparse(value).netloc, allowed)


def tunnel_notice(names) -> str:
    """Printed at startup when the interface has been told to answer to other names."""
    listed = ", ".join(sorted({bare_host(n) for n in names if (n or "").strip()}))
    return ("\n"
            "  ----------------------------------------------------------------\n"
            f"  Also answering to: {listed}\n"
            "  Whoever reaches that name through your proxy still needs the\n"
            "  token in the startup URL, but make sure the proxy is doing its\n"
            "  own authentication too.\n"
            "  ----------------------------------------------------------------\n")


def exposure_banner(host: str, port: int) -> str:
    """Printed at startup when the interface is not on loopback."""
    return ("\n"
            "  ****************************************************************\n"
            f"  *  WARNING: listening on {host}:{port}, not on loopback.\n"
            "  *  Anyone on this network can reach the port. The launch token\n"
            "  *  is all that stands between them and the evidence export,\n"
            "  *  capture control and every record in this assessment.\n"
            "  *  Do not leave this running on a network you are assessing.\n"
            "  *  Other names for this machine need --allowed-host.\n"
            "  ****************************************************************\n")
