#!/usr/bin/env python3

from __future__ import annotations

import ast
from pathlib import Path


OUTPUT_PATH = Path(__file__).with_name("output")
M1 = int.from_bytes(b"message1", "big")
M2 = int.from_bytes(b"message2", "big")
MAX_DELTA = 1 << 22


def parse_output(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}

    for line in path.read_text().splitlines():
        if line.startswith("Q: "):
            values["q"] = int(line[3:])
        elif line.startswith("P: "):
            values["p"] = int(line[3:])
        elif line.startswith("G: "):
            values["g"] = int(line[3:])
        elif line.startswith("Y: "):
            values["y"] = int(line[3:])
        elif line.startswith("(R1, S1): "):
            values["r1"], values["s1"] = ast.literal_eval(line.split(": ", 1)[1])
        elif line.startswith("(R2, S2): "):
            values["r2"], values["s2"] = ast.literal_eval(line.split(": ", 1)[1])

    required = {"q", "p", "g", "y", "r1", "s1", "r2", "s2"}
    missing = sorted(required - values.keys())
    if missing:
        raise ValueError(f"missing values in output file: {', '.join(missing)}")

    return values


def int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def recover_flag(data: dict[str, int]) -> tuple[int, int, int, bytes]:
    q = data["q"]
    p = data["p"]
    g = data["g"]
    y = data["y"]
    r1 = data["r1"]
    s1 = data["s1"]
    r2 = data["r2"]
    s2 = data["s2"]

    rinv1 = pow(r1, -1, q)
    a = (r2 * rinv1) % q
    coeff = (s2 - a * s1) % q
    if coeff == 0:
        raise ValueError("unexpected zero coefficient while recovering k1")

    rhs = (M2 - a * M1) % q
    coeff_inv = pow(coeff, -1, q)

    # For each delta in [0, 2^22), k2 = k1 + delta (mod q).
    # This gives k1(delta) = (rhs - s2 * delta) / coeff mod q.
    # Then x(delta) = (s1 * k1(delta) - m1) / r1 mod q.
    k1_at_zero = (rhs * coeff_inv) % q
    x_at_zero = ((s1 * k1_at_zero - M1) * rinv1) % q
    beta = (s1 * s2 * coeff_inv * rinv1) % q

    # x(delta) = x_at_zero - beta * delta mod q, so we can update g^x cheaply.
    cur = pow(g, x_at_zero, p)
    step = pow(g, (-beta) % q, p)

    for delta in range(MAX_DELTA):
        if cur == y:
            k1 = ((rhs - s2 * delta) * coeff_inv) % q
            x = ((s1 * k1 - M1) * rinv1) % q
            return delta, k1, x, int_to_bytes(x)
        cur = (cur * step) % p

    raise ValueError("failed to recover the flag")


def main() -> None:
    data = parse_output(OUTPUT_PATH)
    delta, k1, x, flag = recover_flag(data)

    print(f"delta = {delta}")
    print(f"k1 = {k1}")
    print(f"x = {x}")
    print(f"flag = {flag.decode()}")


if __name__ == "__main__":
    main()
