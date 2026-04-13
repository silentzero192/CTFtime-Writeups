#!/usr/bin/env python3
import socket
import sys


HOST = "34.126.223.46"
PORT = 17193


def main() -> int:
    payload = "".join(f"{i}\n" for i in range(1, 1001)).encode()

    with socket.create_connection((HOST, PORT)) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)

        while True:
            data = sock.recv(4096)
            if not data:
                break
            sys.stdout.write(data.decode("utf-8", errors="replace"))
            sys.stdout.flush()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
