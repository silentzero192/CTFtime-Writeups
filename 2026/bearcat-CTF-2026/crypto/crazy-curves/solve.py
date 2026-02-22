#!/usr/bin/env python3
import ast
import math
import random
import re
import sys
from hashlib import sha1
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# We only need enough factors so that CRT modulus exceeds 2^128 by a wide margin.
# The remaining unknown factors can then be brute-forced through the ciphertext check.
PARTIAL_FACTORS = {
    "Daquavious Pork": [
        2**3,
        3,
        7,
        17,
        149,
        457,
        4517,
        5749,
        717427,
        1966366126889,
    ],
}


def mul(P, Q, p):
    u1, v1 = P
    u2, v2 = Q
    return ((u1 * u2 - v1 * v2) % p, (u1 * v2 + u2 * v1) % p)


def sqr(P, p):
    u, v = P
    return ((u * u - v * v) % p, (2 * u * v) % p)


def inv(P, p):
    u, v = P
    return (u, (-v) % p)


def pow_elem(P, n, p):
    R = (1, 0)
    Q = P
    e = n
    while e:
        if e & 1:
            R = mul(R, Q, p)
        Q = sqr(Q, p)
        e >>= 1
    return R


def dlog_bsgs(g, h, order, p):
    m = math.isqrt(order) + 1
    table = {}
    cur = (1, 0)
    for j in range(m):
        if cur not in table:
            table[cur] = j
        cur = mul(cur, g, p)

    factor = pow_elem(inv(g, p), m, p)
    gamma = h
    for i in range(m + 1):
        j = table.get(gamma)
        if j is not None:
            x = i * m + j
            if x < order and pow_elem(g, x, p) == h:
                return x
            return x % order
        gamma = mul(gamma, factor, p)
    raise ValueError("BSGS failed")


def dlog_pollard_rho(g, h, q, p, restarts=32, max_steps=10_000_000):
    rng = random.Random(0xBCC7F)

    def step(X, a, b):
        r = X[0] % 3
        if r == 0:
            return mul(X, h, p), a, (b + 1) % q
        if r == 1:
            return sqr(X, p), (2 * a) % q, (2 * b) % q
        return mul(X, g, p), (a + 1) % q, b

    for _ in range(restarts):
        a = rng.randrange(q)
        b = rng.randrange(q)
        x = mul(pow_elem(g, a, p), pow_elem(h, b, p), p)
        y, c, d = x, a, b

        for _ in range(max_steps):
            x, a, b = step(x, a, b)
            y, c, d = step(y, c, d)
            y, c, d = step(y, c, d)
            if x == y:
                num = (a - c) % q
                den = (d - b) % q
                if den == 0:
                    break
                k = (num * pow(den, -1, q)) % q
                if pow_elem(g, k, p) == h:
                    return k
                break
    raise ValueError("Pollard-rho failed")


def crt(remainders, moduli):
    x = 0
    m = 1
    for r, mod in zip(remainders, moduli):
        t = ((r - x) % mod) * pow(m, -1, mod) % mod
        x += m * t
        m *= mod
    return x % m, m


def load_curves(path):
    text = Path(path).read_text()
    match = re.search(r"curves\s*=\s*(\{.*?\})\n\nclass Point", text, re.S)
    if not match:
        raise ValueError("Could not parse curves dictionary")
    return ast.literal_eval(match.group(1))


def load_output(path):
    text = Path(path).read_text()
    am = re.search(r"Alice public key:\s*\((\d+),\s*(\d+)\)", text)
    bm = re.search(r"Bob public key:\s*\((\d+),\s*(\d+)\)", text)
    dm = re.search(r"\{[^\n]*\}", text)
    if not (am and bm and dm):
        raise ValueError("Could not parse output.txt")

    A = (int(am.group(1)), int(am.group(2)))
    B = (int(bm.group(1)), int(bm.group(2)))
    data = ast.literal_eval(dm.group(0))
    iv = bytes.fromhex(data["iv"])
    ct = bytes.fromhex(data["ciphertext"])
    return A, B, iv, ct


def on_curve(P, p, a, b, c):
    x, y = P
    return ((x - a) * (x - a) + (y - b) * (y - b) - c * c) % p == 0


def find_curve(curves, A, B):
    matches = []
    for name, (p, a, b, c, G) in curves.items():
        if on_curve(A, p, a, b, c) and on_curve(B, p, a, b, c):
            matches.append((name, p, a, b, c, G))
    if len(matches) != 1:
        raise ValueError(f"Expected one matching curve, found {len(matches)}")
    return matches[0]


def normalize(P, a, b, c, p):
    inv_c = pow(c, -1, p)
    x, y = P
    return ((x - a) * inv_c % p, (y - b) * inv_c % p)


def recover_b_mod_M(Gn, Bn, p, n, factors):
    residues = []
    moduli = []
    for mod in factors:
        g = pow_elem(Gn, n // mod, p)
        h = pow_elem(Bn, n // mod, p)
        if mod <= 20_000_000:
            k = dlog_bsgs(g, h, mod, p)
        else:
            k = dlog_pollard_rho(g, h, mod, p)
        residues.append(k)
        moduli.append(mod)
    return crt(residues, moduli)


def decrypt_flag_from_candidates(An, p, a, c, iv, ct, b_mod, M):
    lo = 2
    hi = 2**128
    k0 = 0 if b_mod >= lo else (lo - b_mod + M - 1) // M
    b = b_mod + k0 * M
    if b > hi:
        raise ValueError("No private key candidates in [2, 2^128]")

    step = pow_elem(An, M, p)
    shared = pow_elem(An, b, p)
    while b <= hi:
        ss_x = (shared[0] * c + a) % p
        key = sha1(str(ss_x).encode()).digest()[:16]
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
        try:
            msg = unpad(pt, 16)
        except ValueError:
            msg = b""
        if msg.startswith(b"BCCTF{") and msg.endswith(b"}"):
            return msg.decode()
        b += M
        shared = mul(shared, step, p)
    raise ValueError("Flag not found in candidate key space")


def main():
    curves_file = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("crazy_curve.sage")
    output_file = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("output.txt")

    curves = load_curves(curves_file)
    A, B, iv, ct = load_output(output_file)
    name, p, a, b, c, G = find_curve(curves, A, B)

    factors = PARTIAL_FACTORS.get(name)
    if factors is None:
        raise ValueError(f"No factor data configured for curve: {name}")
    if p % 4 != 3:
        raise ValueError("This solver expects p % 4 == 3")

    n = p + 1
    Gn = normalize(G, a, b, c, p)
    An = normalize(A, a, b, c, p)
    Bn = normalize(B, a, b, c, p)

    b_mod, M = recover_b_mod_M(Gn, Bn, p, n, factors)
    flag = decrypt_flag_from_candidates(An, p, a, c, iv, ct, b_mod, M)
    print(flag)


if __name__ == "__main__":
    main()
