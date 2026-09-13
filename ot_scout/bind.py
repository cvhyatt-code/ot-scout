"""Where the web interface may listen, and which requests it will answer.

OT Scout's HTTP interface has no authentication: every endpoint is open to whoever can reach the
port, including evidence export, deleting an engagement together with its captures, and the Scout
Assist model settings (which hold an API key). That is a reasonable shape for a tool bound to loopback
on the assessor's own laptop, and an unreasonable one anywhere else — so a non-loopback bind has to be asked for explicitly.

Binding loopback keeps other machines out. It does not keep out the assessor's own browser acting
on someone else's instructions, which is what the Host and Origin checks below are for.
"""
from __future__ import annotations

from urllib.parse import urlparse

LOOPBACK_NAMES = {"localhost", "::1", "0:0:0:0:0:0:0:1"}

# Names a browser may legitimately use to reach a loopback bind.
LOOPBACK_HOST_HEADERS = frozenset({"127.0.0.1", "localhost", "[::1]", "::1"})

TUNNELS = """Reach a remote collector through something that authenticates, instead:
  ssh -L 8080:localhost:8080 user@collector     # then browse http://127.0.0.1:8080
  tailscale serve --bg --https=8443 8080        # private overlay network, TLS terminated for you

A port forward arrives as 127.0.0.1 and needs nothing further. A reverse proxy that keeps the name
the browser typed — Tailscale Serve does — has to have that name allowed, or every request is
refused with 421:
  sudo python3 run.py --allowed-host laptop.tailnet-name.ts.net"""


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
            f"evidence export, engagement deletion and the Scout Assist API key to anyone who can reach the port.\n\n"
            f"{TUNNELS}\n\n"
            f"If you have read that and still mean it, add --insecure-bind.")


def bare_host(value: str) -> str:
    """A Host header or hostname reduced to the name we compare on: lowercase, no port, no root dot.

    One function so the allowlist and the check can never disagree about what a name is. If they
    could drift, `--allowed-host name:8443` would be accepted at the command line and then silently
    never match, which is the worst way for a security control to fail.
    """
    name = (value or "").strip().lower().rstrip(".")
    if name.startswith("["):                       # [::1]:8080
        return name.partition("]")[0] + "]"
    if name.count(":") == 1:                       # host:port, but not a bare IPv6 literal
        return name.rsplit(":", 1)[0]
    return name


def allowed_hosts(host: str, extra=None) -> frozenset[str] | None:
    """Host header values this server will answer to, or None to accept anything.

    Binding 127.0.0.1 stops other machines connecting. It does not stop a page on the internet from
    pointing a hostname it owns at 127.0.0.1 and having the assessor's own browser fetch from us —
    DNS rebinding. The browser treats the response as belonging to that hostname, so the attacker's
    script can read it: the whole evidence export, from a server that never saw a foreign packet.
    The name the user typed only survives in the Host header, so refusing an unexpected one is the
    only defence a server without authentication has.

    `extra` is how a tunnel the assessor set up gets through. A port forward presents 127.0.0.1 and
    needs nothing; a reverse proxy that preserves the original name — Tailscale Serve does — presents
    a name this process cannot guess, so it has to be told. Naming one is not the same as switching
    the check off: every other name is still refused, which is what stops the rebinding attack.

    A deliberate --insecure-bind is reached by names we cannot enumerate (a tailnet name, a LAN
    hostname, a reverse proxy), so it accepts anything and relies on the startup banner instead.
    """
    if not is_loopback(host):
        return None
    names = {bare_host(n) for n in (extra or ()) if (n or "").strip()}
    return LOOPBACK_HOST_HEADERS | {bare_host(host)} | names


def host_header_ok(value: str | None, allowed: frozenset[str] | None) -> bool:
    """True if a request carrying this Host header may be answered."""
    if allowed is None:
        return True
    if not value:
        return False
    return bare_host(value) in allowed


def origin_ok(value: str | None, allowed: frozenset[str] | None) -> bool:
    """True if a state-changing request carrying this Origin may proceed.

    No Origin means no browser: curl, a script, the CLI. Those carry no ambient authority for a page
    elsewhere to borrow, and refusing them would break every non-browser client for no gain. An
    Origin that is present and foreign is a page somewhere else spending the assessor's access —
    deleting an engagement, overwriting the model API key, starting a capture.
    """
    if allowed is None or value is None:
        return True
    if value == "null":                            # sandboxed iframe, data: document, file://
        return False
    return host_header_ok(urlparse(value).netloc, allowed)


def tunnel_notice(names) -> str:
    """Printed at startup when a loopback bind has been told to answer to other names.

    Not a refusal — a tunnel that authenticates is the recommended way to reach a remote collector,
    and this is what makes it work. But it is the moment the interface stops being reachable only by
    the person sitting at the machine, and the tool says so rather than letting it pass silently."""
    listed = ", ".join(sorted({bare_host(n) for n in names if (n or "").strip()}))
    return ("\n"
            "  ----------------------------------------------------------------\n"
            f"  Also answering to: {listed}\n"
            "  The bind is still loopback, so only something on this machine can\n"
            "  connect — but whoever reaches that name through your tunnel gets\n"
            "  an interface with NO AUTHENTICATION. Make sure the tunnel is what\n"
            "  is doing the authenticating.\n"
            "  ----------------------------------------------------------------\n")


def exposure_banner(host: str, port: int) -> str:
    """Printed at startup when the interface is not on loopback."""
    return ("\n"
            "  ****************************************************************\n"
            f"  *  OT Scout is listening on {host}:{port} with NO AUTHENTICATION.\n"
            "  *  Anyone who can reach this port can:\n"
            "  *    - download the full evidence package for this engagement\n"
            "  *    - delete an engagement, its database and its raw captures\n"
            "  *    - read and overwrite the Scout Assist model API key\n"
            "  *  Do not leave this running on a network you are assessing.\n"
            "  ****************************************************************\n")
