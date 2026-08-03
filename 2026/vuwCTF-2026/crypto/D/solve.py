#!/usr/bin/env python3
"""
VuwCTF 2026 - Crypto - "D"

D.sage builds a 16-round block cipher over GF(2^128) whose only non-linear
component is

    D(13, a)  with  a = F.from_integer(19)

Despite the file name, D is not the programming language: D(n, a) is the
recurrence

    D_0 = 0,  D_1 = y,  D_n = y*D_(n-1) - a*D_(n-2)

whose closed form is A*u^n + B*v^n with u + v = y, u*v = a and
A = (u+v)/(u-v).  In characteristic 2, u - v = u + v, so A = 1 and the
whole thing collapses to the DICKSON POLYNOMIAL OF THE FIRST KIND:

    D_n(y, a) = u^n + v^n

D_n(., a) permutes GF(q) iff gcd(n, q^2 - 1) = 1.  Here n = 13, q = 2^128,
and ord_13(2) = 12 does not divide 256, so 13 does not divide 2^256 - 1:
the "S-box" is a permutation polynomial.

Inverting it uses the composition law

    D_m(D_n(x, a), a^n) = D_(m*n)(x, a)

so with m = 13^-1 mod (q^2 - 1) the inverse of D_13(., a) is D_m(., a^13).
m is astronomically large, so D_m is never built as a polynomial.  Instead
it is evaluated inside the quotient ring

    R = F[T] / (T^2 + c*T + b),    b = a^13

where T and c + T are the two roots u, v.  T |-> c + T is a ring
automorphism swapping them, so if T^m = A + B*T then

    D_m(c, b) = u^m + v^m = (A + B*T) + (A + B*(c + T)) = B*c

Everything else is bookkeeping: the key is random.Random(b"p-box"), i.e.
a fixed seed, and the byte shuffle is a ShiftRows-style bijection.

Usage:  python3 solve.py [flag.png.encrypted] [flag.png]

Pure stdlib, no Sage required.  Runs in ~30 s.
"""

import random
import sys
import time

INFILE = sys.argv[1] if len(sys.argv) > 1 else "flag.png.encrypted"
OUTFILE = sys.argv[2] if len(sys.argv) > 2 else "flag.png"

# ----------------------------------------------------------------------------
# GF(2^128)
# ----------------------------------------------------------------------------
# Sage has no Conway polynomial for GF(2^128) (the database jumps 127 -> 131),
# so GF(2^128) falls back to NTL's minimal-weight modulus:
#
#     x^128 + x^7 + x^2 + x + 1        (low part 0x87, same as AES-GCM)
#
# An element is a plain Python int: bit i is the coefficient of x^i, which is
# exactly Sage's from_integer()/to_integer() convention.

RED = 0x87
M128 = (1 << 128) - 1

# Carry-less multiply via the "spread the bits out" trick: expand each operand
# so that bit i lands in byte slot i, then use one ordinary big-int multiply.
# Each output slot accumulates at most 128 partial products, which fits in a
# byte, so no carry ever crosses a slot boundary.
_EXPAND = [bytes((c >> j) & 1 for j in range(8)) for c in range(256)]
_SLOT_MASK = int.from_bytes(b"\x01" * 256, "little")
_COMPRESS = {bytes((v >> j) & 1 for j in range(8)): v for v in range(256)}


def clmul(a: int, b: int) -> int:
    """Carry-less product of two 128-bit polynomials (255-bit result)."""
    sa = int.from_bytes(b"".join([_EXPAND[c] for c in a.to_bytes(16, "little")]), "little")
    sb = int.from_bytes(b"".join([_EXPAND[c] for c in b.to_bytes(16, "little")]), "little")
    prod = (sa * sb) & _SLOT_MASK
    raw = prod.to_bytes(256, "little")
    return int.from_bytes(bytes([_COMPRESS[raw[i:i + 8]] for i in range(0, 256, 8)]), "little")


def gred(t: int) -> int:
    """Reduce a <=255-bit polynomial modulo x^128 + x^7 + x^2 + x + 1."""
    while t >> 128:
        hi = t >> 128
        t = (t & M128) ^ hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7)
    return t


def gmul(a: int, b: int) -> int:
    return gred(clmul(a, b))


def _linear_tables(f):
    """Byte-window tables for a GF(2)-linear map f (16 x 256 entries)."""
    tabs = []
    for k in range(16):
        tab = [0] * 256
        for v in range(1, 256):
            tab[v] = f(v << (8 * k))
        tabs.append(tab)
    return tabs


def _apply(tabs, a: int) -> int:
    raw = a.to_bytes(16, "little")
    r = 0
    for k in range(16):
        r ^= tabs[k][raw[k]]
    return r


# Squaring is GF(2)-linear, so it is a table lookup rather than a multiply.
_SQ = _linear_tables(lambda z: gred(clmul(z, z)))


def gsqr(a: int) -> int:
    return _apply(_SQ, a)


def gpow(a: int, e: int) -> int:
    r, acc = 1, a
    while e:
        if e & 1:
            r = gmul(r, acc)
        acc = gsqr(acc)
        e >>= 1
    return r


# ----------------------------------------------------------------------------
# The Dickson "S-box" and its inverse
# ----------------------------------------------------------------------------
A = 19                     # F.from_integer(19) = x^4 + x + 1
B = gpow(A, 13)            # parameter of the inverse Dickson polynomial
_MULB = _linear_tables(lambda z: gmul(z, B))   # multiply-by-B is linear too


def dickson13(z: int) -> int:
    """D_13(z, A) -- evaluate the recurrence directly at z."""
    d0, d1 = 0, z
    for _ in range(12):
        d0, d1 = d1, gmul(z, d1) ^ gmul(A, d0)
    return d1


# m = 13^-1 mod (2^256 - 1) = 0x7 627 627 ... 627  (the block 627 repeats 21x).
# That regular structure lets the exponentiation walk base-2^12 digits, which
# costs 21 multiplications instead of the ~129 a naive square-and-multiply
# would need.
M_EXP = pow(13, -1, (1 << 256) - 1)
M_DIGITS = [0x7] + [0x627] * 21
assert sum(d << (12 * i) for i, d in enumerate(reversed(M_DIGITS))) == M_EXP


def dickson13_inv(c: int) -> int:
    """The unique z with D_13(z, A) == c, via D_m(c, A^13)."""
    if c == 0:
        return 0

    # arithmetic in R = F[T]/(T^2 + c*T + B); an element is (r0, r1) = r0 + r1*T
    def rsqr(r):
        s0, s1 = gsqr(r[0]), gsqr(r[1])
        return (s0 ^ _apply(_MULB, s1), gmul(s1, c))

    def rmul(x, y):
        p = gmul(x[0], y[0])
        q = gmul(x[1], y[1])
        r = gmul(x[0] ^ x[1], y[0] ^ y[1])
        return (p ^ _apply(_MULB, q), r ^ p ^ q ^ gmul(q, c))

    def rpow_small(x, e):
        acc, bit = (1, 0), 1 << (e.bit_length() - 1)
        while bit:
            acc = rsqr(acc)
            if e & bit:
                acc = rmul(acc, x)
            bit >>= 1
        return acc

    T = (0, 1)
    step = rpow_small(T, M_DIGITS[1])          # T^0x627, reused every digit
    acc = rpow_small(T, M_DIGITS[0])           # leading digit
    for _ in M_DIGITS[1:]:
        for _ in range(12):                    # acc = acc^(2^12)
            acc = rsqr(acc)
        acc = rmul(acc, step)

    return gmul(acc[1], c)                     # D_m(c, B) = B_coeff * c


# ----------------------------------------------------------------------------
# Cipher
# ----------------------------------------------------------------------------
def keystream():
    """The 128 values yielded by ks() before it repeats."""
    key = random.Random(b"p-box").randbytes(128)
    out = []
    for i in range(8):
        l = int.from_bytes(key[i:i + 16], "big")   # F.from_bytes -> from_integer
        for _ in range(16):
            out.append(l)
            l = dickson13(l)
    return out


# c[j*4 + i] = b[i + 4*((j + i) % 4)] -- a ShiftRows-style byte permutation
PBOX = [0] * 16
for i in range(4):
    for j in range(4):
        PBOX[j * 4 + i] = i + 4 * ((j + i) % 4)


def encrypt_block(block: bytes, ks: list, base: int) -> bytes:
    b = int.from_bytes(block, "big")
    for r in range(16):
        e = dickson13(ks[(base + r) % 128] ^ b)
        raw = e.to_bytes(16, "big")            # to_bytes() length = 16 here
        b = int.from_bytes(bytes(raw[PBOX[d]] for d in range(16)), "big")
    return b.to_bytes(16, "big")


def decrypt_block(block: bytes, ks: list, base: int) -> bytes:
    b = int.from_bytes(block, "big")
    for r in range(15, -1, -1):
        cur = b.to_bytes(16, "big")
        raw = bytearray(16)
        for d in range(16):
            raw[PBOX[d]] = cur[d]              # undo the shuffle
        b = dickson13_inv(int.from_bytes(bytes(raw), "big")) ^ ks[(base + r) % 128]
    return b.to_bytes(16, "big")


def main():
    ct = open(INFILE, "rb").read()
    assert len(ct) % 16 == 0, "ciphertext is not a whole number of blocks"
    nblocks = len(ct) // 16

    # sanity: the inverse really does invert the S-box
    for t in (1, 19, 0xdeadbeef, M128):
        assert dickson13_inv(dickson13(t)) == t
    print("[+] D_13 inverse verified", file=sys.stderr)

    ks = keystream()
    print("[+] keystream derived from random.Random(b'p-box')", file=sys.stderr)

    out = bytearray()
    prev = bytes(16)                            # CBC IV = s = bytes(16)
    t0 = time.time()
    for n in range(nblocks):
        cur = ct[n * 16:n * 16 + 16]
        dec = decrypt_block(cur, ks, n * 16)
        out += bytes(x ^ y for x, y in zip(dec, prev))
        prev = cur
        if n % 25 == 0 or n == nblocks - 1:
            done = n + 1
            print("\r[*] block %4d/%d  (%.0f%%, %.1fs)"
                  % (done, nblocks, 100 * done / nblocks, time.time() - t0),
                  end="", file=sys.stderr)
    print(file=sys.stderr)

    # re-encrypt and compare: proves the recovered plaintext is exact
    chk, prev = bytearray(), bytes(16)
    for n in range(nblocks):
        prev = encrypt_block(bytes(x ^ y for x, y in zip(out[n * 16:n * 16 + 16], prev)),
                             ks, n * 16)
        chk += prev
    assert bytes(chk) == ct, "re-encryption mismatch"
    print("[+] re-encryption matches the ciphertext exactly", file=sys.stderr)

    # the padding is only applied when len(flag) % 16 != 0
    pad = out[-1]
    if 1 <= pad <= 15 and out[-pad:] == bytes([pad]) * pad:
        out = out[:-pad]
        print("[+] stripped %d padding bytes" % pad, file=sys.stderr)

    assert out[:8] == b"\x89PNG\r\n\x1a\n" and out[-8:] == b"IEND\xaeB`\x82"
    open(OUTFILE, "wb").write(bytes(out))
    print("[+] wrote %s (%d bytes) - open it to read the flag" % (OUTFILE, len(out)),
          file=sys.stderr)


if __name__ == "__main__":
    main()
