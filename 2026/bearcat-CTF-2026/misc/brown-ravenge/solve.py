#!/usr/bin/env python3
import argparse
import re
import socket
import sys


PROMPT = b"Enter the access string: "


def de_bruijn_binary(order: int) -> str:
    """Return a cyclic binary de Bruijn sequence B(2, order)."""
    alphabet_size = 2
    a = [0] * (alphabet_size * order)
    sequence = []

    def db(t: int, p: int) -> None:
        if t > order:
            if order % p == 0:
                sequence.extend(a[1 : p + 1])
            return

        a[t] = a[t - p]
        db(t + 1, p)
        for j in range(a[t - p] + 1, alphabet_size):
            a[t] = j
            db(t + 1, t)

    db(1, 1)
    return "".join(map(str, sequence))


def build_payload(order: int = 12) -> str:
    cyclic = de_bruijn_binary(order)
    linear = cyclic + cyclic[: order - 1]
    return linear


def recv_until(sock: socket.socket, marker: bytes, buf: bytes) -> tuple[bytes, bytes]:
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("Connection closed before expected prompt.")
        buf += chunk
    split = buf.index(marker) + len(marker)
    return buf[:split], buf[split:]


def main() -> None:
    parser = argparse.ArgumentParser(description="BCCTF Da Brown's Revenge solver")
    parser.add_argument("--host", default="chal.bearcatctf.io")
    parser.add_argument("--port", type=int, default=19679)
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    payload = build_payload(12)
    if len(payload) != 4107:
        raise ValueError(f"Unexpected payload length: {len(payload)}")

    payload_bytes = payload.encode() + b"\n"
    remaining = b""

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.settimeout(args.timeout)

        for _ in range(args.rounds):
            prompt_block, remaining = recv_until(sock, PROMPT, remaining)
            sys.stdout.write(prompt_block.decode(errors="replace"))
            sys.stdout.flush()
            sock.sendall(payload_bytes)

        # Collect trailing output (including the flag).
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            remaining += chunk

    tail = remaining.decode(errors="replace")
    print(tail, end="")

    match = re.search(r"BCCTF\{[^}\n]+\}", tail)
    if match:
        print(f"\n[+] Flag: {match.group(0)}")


if __name__ == "__main__":
    main()
