#!/usr/bin/env python3
"""Mixed Moose EX (vuwCTF 2026) -- recover moose.jpg from moose.bin.

The packer applies, in place and in increasing index order:

    for i = 0 .. n-1:   w[i] ^= scramble(w[permute(i, n)])

Each step writes exactly one cell and `permute` is a fixed-point-free
permutation, so the inverse is the identical operation run in reverse order.
"""
import struct
from vm import run, rotl, rotr, M


def scramble(x):                       # sym.func.100000a0c
    v = x & M
    v ^= 0x5abcdef7
    v = rotl(v, 5)
    v = rotl(v, v >> 27)               # data-dependent rotate
    v ^= v >> 16
    v = (v * 0x7feb352d) & M
    v ^= v >> 15
    v = run(1, v, 0, 0, 0)             # prog1
    v = (v * 0x846ca68b) & M
    v ^= v >> 13
    v = rotr(v, (v >> 3) & 0x1f)
    v = (v + 0x13371337) & M
    return v


def permute(i, n):                     # sym.func.100000b54
    if n <= 1:
        return 0
    bits = 2
    while (1 << bits) < n:
        bits += 2
    half = bits // 2
    return run(2, i, half, (1 << half) - 1, n)   # prog2


raw = bytearray(open("moose.bin", "rb").read())
n = len(raw) // 4                      # trailing len%4 bytes pass through
print("len", len(raw), "words", n)
data = list(struct.unpack_from("<%dI" % n, raw, 0))

g = [permute(i, n) for i in range(n)]
assert len(set(g)) == n, "g is not a permutation"
assert not any(g[i] == i for i in range(n)), "fixed point -> not invertible"
print("permutation? True  fixed points: 0")

for i in range(n - 1, -1, -1):         # reverse order is the whole trick
    data[i] ^= scramble(data[g[i]])
    data[i] &= M

struct.pack_into("<%dI" % n, raw, 0, *data)
open("recovered.jpg", "wb").write(raw)
print("magic:", raw[:4].hex(), "tail:", raw[-4:].hex())
