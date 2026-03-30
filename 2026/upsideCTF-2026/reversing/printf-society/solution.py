#!/usr/bin/env python3
import math
import re
import socket
import sys
import time


HOST = "140.245.25.63"
PORT = 8011
PROMPT = b"Guess a number (0-99): "
OFFSETS = [0, -1, 1, -2, 2]
SLACKS = [0.03, 0.08, 0.15]


def recv_until(sock: socket.socket, buf: bytes, marker: bytes) -> tuple[bytes, bytes]:
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed before prompt")
        buf += chunk
    split = buf.index(marker) + len(marker)
    return buf[:split], buf[split:]


def recv_all(sock: socket.socket, buf: bytes = b"") -> bytes:
    sock.settimeout(1.0)
    while True:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def wait_for_boundary(slack: float) -> int:
    target = math.floor(time.time()) + 1 + slack
    while True:
        now = time.time()
        if now >= target:
            return int(now)
        time.sleep(min(0.001, target - now))


def play_once(offset: int, slack: float) -> str:
    with socket.create_connection((HOST, PORT), timeout=3.0) as sock:
        sock.settimeout(3.0)
        buf = b""
        transcript = []
        for _ in range(5):
            chunk, buf = recv_until(sock, buf, PROMPT)
            transcript.append(chunk.decode("utf-8", errors="replace"))
            current_second = wait_for_boundary(slack)
            guess = (current_second + offset) % 100
            sock.sendall(f"{guess}\n".encode())
            transcript.append(f"{guess}\n")
        tail = recv_all(sock, buf).decode("utf-8", errors="replace")
        transcript.append(tail)
    return "".join(transcript)


def extract_flag(text: str) -> str | None:
    match = re.search(r"(CTF\{[^}\n]+\}|flag\{[^}\n]+\})", text)
    return match.group(1) if match else None


def main() -> int:
    for slack in SLACKS:
        for offset in OFFSETS:
            try:
                transcript = play_once(offset, slack)
            except (OSError, EOFError, TimeoutError) as exc:
                print(f"[!] offset={offset:+d} slack={slack:.2f} failed: {exc}")
                continue

            print(f"[*] offset={offset:+d} slack={slack:.2f}")
            print(transcript)

            flag = extract_flag(transcript)
            if flag:
                print(f"[+] FLAG = {flag}")
                return 0

    print("[-] no flag recovered")
    return 1


if __name__ == "__main__":
    sys.exit(main())
