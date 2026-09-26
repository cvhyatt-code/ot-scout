#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from ot_scout import __version__, edition
from ot_scout.bind import TUNNELS, exposure_banner, is_loopback, tunnel_notice
from ot_scout.capture import CaptureManager
from ot_scout.modules import activate
from ot_scout.paths import default_data_dir, hand_back
from ot_scout.store import Store
from ot_scout.web import AppServer, Handler

DEFAULT_PORT = 8767


def startup_lines(host: str, port: int, token: str) -> list[str]:
    """What to print at launch: the product, the version and the URL to open, token included."""
    shown = "localhost" if is_loopback(host) or host in ("0.0.0.0", "::", "") else host
    lines = [f"{edition.NAME} v{__version__}: http://{shown}:{port}/?token={token}"]
    if is_loopback(host):
        lines.append(f"  (or http://127.0.0.1:{port}/?token={token})")
    return lines


def build_server(args):
    data_dir = Path(args.data_dir).expanduser() if args.data_dir else default_data_dir(edition.DATA_DIR_NAME)
    data_dir.mkdir(parents=True, exist_ok=True)
    extensions = activate(edition.MODULES)
    store = Store(str(data_dir / "assessment.db"))
    capture = CaptureManager(store, data_dir / "captures")
    server = AppServer((args.host, args.port), Handler, store, capture, allowed=args.allowed_host,
                       extensions=extensions, data_dir=data_dir)
    if args.demo:
        server.ensure_demo()
        server._adopt(Store(server.demo_database))
    hand_back(data_dir)
    return server, capture, data_dir


def main(argv=None):
    parser = argparse.ArgumentParser(description=f"{edition.NAME}: passive OT/ICS assessment")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Web bind address (default: 127.0.0.1). Anything else prints a warning.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Web port (default: {DEFAULT_PORT})")
    parser.add_argument("--allowed-host", action="append", default=[], metavar="NAME",
                        help="Also answer to this Host header, e.g. a reverse proxy that keeps the name the "
                             "browser typed. Repeatable.")
    parser.add_argument("--data-dir", default=None,
                        help=f"Where the data lives (default: ~/.local/share/{edition.DATA_DIR_NAME}/; "
                             "under sudo, the invoking user's)")
    parser.add_argument("--demo", action="store_true",
                        help="Open the fictitious demonstration data set, building it first if needed. No sudo needed.")
    args = parser.parse_args(argv)

    server, capture, data_dir = build_server(args)
    for line in startup_lines(args.host, server.server_address[1], server.token):
        print(line)
    print(f"Data: {data_dir}")
    if args.demo:
        print("Showing the fictitious demonstration data set.")
    print("Open the URL above, token included. Live packet capture requires root and Linux; nothing else does.")
    if is_loopback(args.host):
        if args.allowed_host:
            print(tunnel_notice(args.allowed_host))
    else:
        print(exposure_banner(args.host, server.server_address[1]))
        print(TUNNELS)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        capture.stop()
        server.server_close()
        hand_back(data_dir)


if __name__ == "__main__":
    main()
