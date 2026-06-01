#!/usr/bin/env python3
import math
import re
from pathlib import Path


def parse_values(path: Path):
    text = path.read_text()
    vals = {}
    for key in ("n", "e", "c"):
        m = re.search(rf"{key}\s*=\s*(0x[0-9a-fA-F]+)", text)
        if not m:
            raise ValueError(f"missing {key} in {path}")
        vals[key] = int(m.group(1), 16)
    return vals["n"], vals["e"], vals["c"]


def long_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def p_adic_log_mod_p4(z: int, p: int) -> int:
    # For z in 1 + pZ (mod p^4):
    # log(z) = t - t^2/2 + t^3/3 (mod p^4), t = z - 1.
    mod = p**4
    t = (z - 1) % mod
    inv2 = pow(2, -1, mod)
    inv3 = pow(3, -1, mod)
    return (t - (t * t % mod) * inv2 + (t * t % mod * t % mod) * inv3) % mod


def main():
    n, e, c = parse_values(Path("data.txt"))

    # n is p^4 and both e,c are in 1+pZ, so we can work in this p-adic subgroup.
    p = math.gcd(c - 1, n)
    if p <= 1:
        raise ValueError("failed to recover p")
    if p**4 != n:
        raise ValueError("expected n = p^4 for this challenge")

    le = p_adic_log_mod_p4(e, p)
    lc = p_adic_log_mod_p4(c, p)

    # Divide logs by p, then solve x from: log(c)/p = x * log(e)/p (mod p^3).
    mod = p**3
    le1 = (le // p) % mod
    lc1 = (lc // p) % mod
    x = (lc1 * pow(le1, -1, mod)) % mod

    if pow(e, x, n) != c:
        raise ValueError("sanity check failed: recovered exponent does not satisfy e^x = c (mod n)")

    msg = long_to_bytes(x)
    m = re.search(rb"SK-CERT\{[^}]+\}", msg)
    if not m:
        raise ValueError("flag pattern not found")

    print(m.group(0).decode())


if __name__ == "__main__":
    main()
