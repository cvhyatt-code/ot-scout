#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from ot_scout import __version__
from ot_scout.bind import bind_refusal, exposure_banner, is_loopback, tunnel_notice
from ot_scout.capture import CaptureManager
from ot_scout.store import Store
from ot_scout.web import AppServer, Handler


def main():
    parser = argparse.ArgumentParser(description="Passive OT/ICS assessment tool")
    parser.add_argument("--host", default="127.0.0.1", help="Web bind address (default: localhost only)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--allowed-host", action="append", default=[], metavar="NAME",
                        help="Also answer to this Host header. Needed when a reverse proxy keeps the name "
                             "the browser typed, as Tailscale Serve does. Repeatable.")
    parser.add_argument("--database", default=str(Path(__file__).parent / "data" / "ot_scout_v4.db"))
    parser.add_argument("--insecure-bind", action="store_true",
                        help="Permit a non-loopback bind address. The web interface has no authentication.")
    args = parser.parse_args()

    refusal = bind_refusal(args.host, args.insecure_bind)
    if refusal:
        parser.error(refusal)

    store = Store(args.database)
    capture = CaptureManager(store)
    server = AppServer((args.host, args.port), Handler, store, capture, allowed=args.allowed_host)
    server.main_database = args.database
    server.demo_database = str(Path(args.database).parent / "demo.db")
    print(f"OT Scout v{__version__}: http://{args.host}:{args.port}")
    print("Live packet capture requires root and Linux.")
    if is_loopback(args.host):
        print("The web interface is bound to localhost.")
        if args.allowed_host:
            print(tunnel_notice(args.allowed_host))
    else:
        print(exposure_banner(args.host, args.port))
        if args.allowed_host:
            print("--allowed-host is ignored on a non-loopback bind: that bind already answers to any name.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        capture.stop()
        server.server_close()


if __name__ == "__main__":
    main()
