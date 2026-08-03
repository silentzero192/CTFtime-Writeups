#!/usr/bin/env python3
"""
VuwCTF 2026 - Crypto / nom-nom

Vulnerability: Håstad's "small message" / low-exponent cube-root attack.

The server encrypts with e = 3 over an RSA modulus n ~ 2048 bits:

    c_flag_inner = flag_inner^3 mod n      (flag_inner is 16 bytes)
    c_flag       = flag^3 mod n            (flag is 23 bytes)

Because flag_inner (128 bits) and flag (184 bits) are both much smaller than
n^(1/3) (~ 683 bits), the modular reduction never "wraps around":

    flag_inner^3  <  n     and     flag^3  <  n

so the ciphertexts are exact integer cubes. Recover the plaintext with an
integer (floor) cube root - no factoring of n needed at all.

Run:
    python3 solve.py
"""

import re
import math
from pathlib import Path

import gmpy2


def integer_cuberoot(n: int) -> int:
    """Exact integer cube root: returns x such that x^3 <= n < (x+1)^3."""
    root, exact = gmpy2.iroot(n, 3)  # fast, exact floor cube root
    assert exact, "ciphertext is not an exact cube!"
    return int(root)


def load_params(path: str) -> dict:
    """Parse the e= / n= / c_flag_inner= / c_flag= lines from nom-nom.txt."""
    params = {}
    text = Path(path).read_text()
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        params[key.strip()] = int(value.strip())
    return params


def main() -> None:
    here = Path(__file__).parent
    params = load_params(here / "nom-nom.txt")

    e = params["e"]
    n = params["n"]
    c_flag_inner = params["c_flag_inner"]
    c_flag = params["c_flag"]

    print(f"[*] e = {e}")
    print(f"[*] n = {n}")
    print(f"[*] c_flag_inner = {c_flag_inner}")
    print(f"[*] c_flag       = {c_flag}")

    # ---- Attack: plaintext = integer cube root of the ciphertext ----
    m_flag_inner = integer_cuberoot(c_flag_inner)
    m_flag = integer_cuberoot(c_flag)

    flag_inner = m_flag_inner.to_bytes(16, "big")
    flag = m_flag.to_bytes(24, "big")

    # ---- Sanity checks (must both be True) ----
    assert pow(m_flag_inner, e, n) == c_flag_inner, "cube root failed for inner"
    assert pow(m_flag, e, n) == c_flag, "cube root failed for full flag"
    assert flag == b"VuwCTF{" + flag_inner + b"}"

    print(f"[+] flag_inner bytes : {flag_inner!r}")
    print(f"[+] flag            : {flag.decode()}")


if __name__ == "__main__":
    main()
