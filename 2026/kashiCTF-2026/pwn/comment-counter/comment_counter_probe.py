#!/usr/bin/env python3
import argparse
import select
import socket
import sys
import time


HOST = "34.126.223.46"
PORT = 17193


def recv_some(sock: socket.socket, duration: float) -> bytes:
    end = time.time() + duration
    chunks = []
    while time.time() < end:
        timeout = max(0.0, end - time.time())
        ready, _, _ = select.select([sock], [], [], timeout)
        if not ready:
            break
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("lines", nargs="*")
    args = parser.parse_args()

    with socket.create_connection((HOST, PORT)) as sock:
        banner = recv_some(sock, 0.5)
        if banner:
            sys.stdout.write(banner.decode("utf-8", errors="replace"))
            sys.stdout.flush()

        if args.delay:
            time.sleep(args.delay)

        for line in args.lines:
            sock.sendall(line.encode() + b"\n")
            time.sleep(0.02)

        tail = recv_some(sock, 5.0)
        if tail:
            sys.stdout.write(tail.decode("utf-8", errors="replace"))
            sys.stdout.flush()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
