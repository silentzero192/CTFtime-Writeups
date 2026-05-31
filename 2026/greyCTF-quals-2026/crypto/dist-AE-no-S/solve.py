#!/usr/bin/env python3
"""
Solve script for AE-no-S: AES without SubBytes.

The cipher is purely linear over GF(2)^128 (only XOR, ShiftRows, MixColumns,
and a linear key schedule remain). Encryption is an affine map:

    C = E(P) = L(P) ^ E(0)

We are given:
  - E(0)       (encryption of the all-zero block)
  - E(e_i)     (encryption of each standard basis vector, i = 0..127)
  - C_flag     (the encrypted flag)

From these we compute  L(e_i) = E(e_i) ^ E(0)  which form the columns of L.

Then for each ciphertext block we solve the linear system L(P) = C_block ^ E(0)
over GF(2) via Gaussian elimination.
"""

import json
from pathlib import Path

HERE = Path(__file__).parent


def bytes_to_bits(data: bytes) -> list[int]:
    """Convert bytes to a list of 128 bits (MSB first)."""
    return [(data[i // 8] >> (7 - (i % 8))) & 1 for i in range(len(data) * 8)]


def bits_to_bytes(bits: list[int]) -> bytes:
    """Convert a list of 128 bits back to 16 bytes (MSB first)."""
    pt = bytearray(16)
    for i in range(128):
        if bits[i]:
            pt[i // 8] |= 1 << (7 - (i % 8))
    return bytes(pt)


def gf2_elimination(A: list[list[int]], b: list[int]) -> list[int]:
    """Solve A x = b over GF(2) via Gaussian elimination (reduced row echelon).
    A is n×n, b is length n.  Returns x as a list of bits.
    """
    n = len(A)
    aug = [row[:] + [b[i]] for i, row in enumerate(A)]

    for col in range(n):
        pivot = None
        for row in range(col, n):
            if aug[row][col]:
                pivot = row
                break
        if pivot is None:
            raise ValueError(f"Matrix is singular at column {col}")
        aug[col], aug[pivot] = aug[pivot], aug[col]
        for row in range(n):
            if row != col and aug[row][col]:
                for c in range(col, n + 1):
                    aug[row][c] ^= aug[col][c]

    return [aug[i][n] for i in range(n)]


def main() -> None:
    with open(HERE / "output.txt") as f:
        data = json.load(f)

    zero_ct = bytes.fromhex(data["zero"]["ct"])
    basis_pairs = data["basis_pairs"]
    flag_ct = bytes.fromhex(data["flag_ct"])

    # ── Build the linear map L ──────────────────────────────────────────
    # L(e_j) = E(e_j) ^ E(0)   (column j of the matrix)
    deltas = []
    for pair in basis_pairs:
        ct = bytes.fromhex(pair["ct"])
        deltas.append(bytes(a ^ b for a, b in zip(ct, zero_ct)))

    # 128×128 matrix over GF(2):  M[i][j] = bit i of L(e_j)
    M = [[0] * 128 for _ in range(128)]
    for j in range(128):
        bits = bytes_to_bits(deltas[j])
        for i in range(128):
            M[i][j] = bits[i]

    # ── Decrypt each flag block ─────────────────────────────────────────
    plaintext = b""
    for offset in range(0, len(flag_ct), 16):
        block_ct = flag_ct[offset : offset + 16]
        y = bytes(a ^ b for a, b in zip(block_ct, zero_ct))
        y_bits = bytes_to_bits(y)
        x_bits = gf2_elimination(M, y_bits)
        plaintext += bits_to_bytes(x_bits)

    # Strip PKCS7 padding
    pad_len = plaintext[-1]
    plaintext = plaintext[:-pad_len]

    print(plaintext.decode())


if __name__ == "__main__":
    main()
