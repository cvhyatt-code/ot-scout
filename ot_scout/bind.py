"""Where the web interface may listen.

OT Scout's HTTP interface has no authentication: every endpoint is open to whoever can reach the
port, including evidence export, database reset and the Scout Assist model settings (which hold an
API key). That is a reasonable shape for a tool bound to loopback on the assessor's own laptop, and
an unreasonable one anywhere else — so a non-loopback bind has to be asked for explicitly.
"""
from __future__ import annotations

LOOPBACK_NAMES = {"localhost", "::1", "0:0:0:0:0:0:0:1"}

TUNNELS = """Reach a remote collector through something that authenticates, instead:
  ssh -L 8080:localhost:8080 user@collector     # then browse http://127.0.0.1:8080
  tailscale serve --bg --https=8443 8080        # private overlay network, TLS terminated for you"""


def is_loopback(host: str) -> bool:
    """True if binding this address keeps the interface on the machine itself."""
    value = (host or "").strip().lower()
    if not value:
        return False
    return value in LOOPBACK_NAMES or value.split("%")[0].startswith("127.")


def bind_refusal(host: str, insecure: bool) -> str | None:
    """The reason this bind address is refused, or None if it is allowed."""
    if is_loopback(host) or insecure:
        return None
    return (f"refusing to bind {host}: the web interface has no authentication, so this would expose "
            f"evidence export, database reset and the Scout Assist API key to anyone who can reach the port.\n\n"
            f"{TUNNELS}\n\n"
            f"If you have read that and still mean it, add --insecure-bind.")


def exposure_banner(host: str, port: int) -> str:
    """Printed at startup when the interface is not on loopback."""
    return ("\n"
            "  ****************************************************************\n"
            f"  *  OT Scout is listening on {host}:{port} with NO AUTHENTICATION.\n"
            "  *  Anyone who can reach this port can:\n"
            "  *    - download the full evidence package for this engagement\n"
            "  *    - reset the assessment database\n"
            "  *    - read and overwrite the Scout Assist model API key\n"
            "  *  Do not leave this running on a network you are assessing.\n"
            "  ****************************************************************\n")
