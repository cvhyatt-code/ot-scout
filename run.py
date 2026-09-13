#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from ot_scout import __version__
from ot_scout.bind import bind_refusal, exposure_banner, is_loopback
from ot_scout.capture import CaptureManager
from ot_scout.store import Store
from ot_scout.web import AppServer, Handler


def main():
    parser = argparse.ArgumentParser(description="Passive OT discovery prototype")
    parser.add_argument("--host", default="127.0.0.1", help="Web bind address (default: localhost only)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--database", default=str(Path(__file__).parent / "data" / "ot_scout_v4.db"))
    parser.add_argument("--insecure-bind", action="store_true",
                        help="Permit a non-loopback bind address. The web interface has no authentication.")
    args = parser.parse_args()

    refusal = bind_refusal(args.host, args.insecure_bind)
    if refusal:
        parser.error(refusal)

    store = Store(args.database)
    capture = CaptureManager(store)
    server = AppServer((args.host, args.port), Handler, store, capture)
    server.main_database = args.database
    server.demo_database = str(Path(args.database).parent / "demo.db")
    print(f"OT Scout prototype v{__version__}: http://{args.host}:{args.port}")
    print("Live packet capture requires root and Linux.")
    if is_loopback(args.host):
        print("The web interface is bound to localhost.")
    else:
        print(exposure_banner(args.host, args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        capture.stop()
        server.server_close()


if __name__ == "__main__":
    main()
