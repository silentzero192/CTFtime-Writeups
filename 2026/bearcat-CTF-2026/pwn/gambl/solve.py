#!/usr/bin/env python3
import argparse
import re
import socket


MENU_RE = re.compile(rb"It is day (\d+) and you have ([0-9]+\.[0-9]+) dollars")


def recv_until(sock, token: bytes) -> bytes:
    data = b""
    while token not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data


def recv_menu(sock):
    data = recv_until(sock, b" > ")
    match = MENU_RE.search(data)
    if not match:
        raise RuntimeError(f"menu parse failed: {data!r}")
    day = int(match.group(1))
    money = float(match.group(2))
    return day, money


def sendline(sock, text: str):
    sock.sendall(text.encode() + b"\n")


def invest(sock, amount: float):
    sendline(sock, "2")
    recv_until(sock, b"investment amount > ")
    sendline(sock, f"{amount:.2f}")
    return recv_menu(sock)


def complete_day(sock):
    sendline(sock, "3")
    return recv_menu(sock)


def solve(host: str, port: int, progress_interval: int = 5):
    target = 5_000_000.0
    with socket.create_connection((host, port), timeout=8) as sock:
        sock.settimeout(8)
        day, money = recv_menu(sock)
        good_days = 0
        print(f"start day={day} money={money:.2f}", flush=True)

        while money < target:
            # Good day: compound with near-full investment.
            day, money = invest(sock, max(0.0, money - 0.01))
            day, money = complete_day(sock)
            good_days += 1
            if money >= target or (
                progress_interval > 0 and good_days % progress_interval == 0
            ):
                print(f"good#{good_days}: day={day} money={money:.2f}", flush=True)

            if money >= target:
                break

            # Bad day: overwrite investedMoney with a second invest(0.0),
            # forcing the < 75% check and resetting i/day bookkeeping.
            day, money = invest(sock, max(0.01, money * 0.50))
            day, money = invest(sock, 0.0)
            day, money = complete_day(sock)

        print(f"before_buy day={day} money={money:.2f}", flush=True)
        sendline(sock, "4")
        output = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                output += chunk
        except OSError:
            pass

    text = output.decode(errors="ignore")
    print(text.strip())


def main():
    parser = argparse.ArgumentParser(description="BCCTF 2026 - gambl solver")
    parser.add_argument("--host", default="chal.bearcatctf.io")
    parser.add_argument("--port", type=int, default=22723)
    parser.add_argument(
        "--progress-interval",
        type=int,
        default=5,
        help="Print progress every N profitable cycles (0 disables periodic logs).",
    )
    args = parser.parse_args()
    solve(args.host, args.port, args.progress_interval)


if __name__ == "__main__":
    main()
