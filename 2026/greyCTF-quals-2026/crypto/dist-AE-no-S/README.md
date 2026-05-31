# AE-no-S — greyCTF Quals 2026

**Category:** `Crypto`  

> So you know how the S in AES does not stand for SubBytes, but rather Standard?  
> That clearly means SubBytes is NOT NECESSARY!!!! :D... right?

---

## Challenge Overview

We are given a Python implementation of AES-128 where **SubBytes has been removed** (replaced with the identity function).  The key schedule is similarly neutered — `SubWord` is replaced with identity, leaving only `RotWord` and the XOR of `RCON` constants.

We receive three pieces of data:

1. **`zero`** — the encryption of the all-zero plaintext block, i.e. `E(0)`.
2. **`basis_pairs`** — 128 plaintext–ciphertext pairs where each plaintext has exactly **one bit set** (the 128 standard basis vectors of GF(2)¹²⁸).
3. **`flag_ct`** — the encrypted flag (48 bytes = 3 AES blocks).

The goal is to recover the plaintext flag.

---

## Vulnerability Analysis

Standard AES consists of four operations per round:

| Operation     | Linearity over GF(2)¹²⁸ |
|---------------|--------------------------|
| **SubBytes**  | ❌ **non-linear** (S-box) |
| **ShiftRows** | ✅ linear (byte permutation) |
| **MixColumns**| ✅ linear (fixed matrix mul over GF(2)⁸, linear over GF(2)¹²⁸) |
| **AddRoundKey**| ✅ linear (XOR) |

**SubBytes is the only source of non-linearity in AES.**  Without it, every operation in the cipher is linear over GF(2)¹²⁸ (XOR is linear, byte permutations are linear, and MixColumns is a fixed linear transformation).  The key schedule also stays linear — `RotWord` is a permutation, `RCON` constants are known, and the only remaining operation is XOR.

Therefore the entire encryption function is an **affine map** over GF(2)¹²⁸:

\[
C = E(P) = L(P) \oplus E(0)
\]

where:
- \(L\) is a **linear** transformation (a \(128 \times 128\) matrix over GF(2)),
- \(E(0)\) is the encryption of the all-zero block (a constant offset).

---

## Solution Approach

Since the system is linear, recovering the plaintext is straightforward:

### Step 1 — Compute the columns of \(L\)

For each standard basis vector \(e_i\) (a plaintext with a single bit set at position \(i\)), we have:

\[
L(e_i) = E(e_i) \oplus E(0)
\]

This gives us the \(i\)-th column of the matrix \(L\).  We compute this for all 128 basis vectors.

### Step 2 — Build the linear system

For any plaintext \(P = \bigoplus_{i} x_i e_i\) (where \(x_i \in \{0,1\}\)), linearity gives:

\[
L(P) = \bigoplus_{i} x_i \cdot L(e_i)
\]

Equivalently, if we assemble the \(128 \times 128\) matrix \(M\) whose \(j\)-th column is the 128-bit vector \(L(e_j)\), then for any ciphertext block \(C\) we want to solve:

\[
M \cdot x = C \oplus E(0)
\]

where \(x \in \{0,1\}^{128}\) is the unknown plaintext (expressed as bits).

### Step 3 — Solve over GF(2)

This is a standard linear system over GF(2).  We perform **Gaussian elimination** (reduced row echelon form) on the augmented matrix \([M \mid C \oplus E(0)]\) to obtain the plaintext bits \(x\).

### Step 4 — Recover the flag

The flag ciphertext is 48 bytes (3 AES blocks).  We apply the same decryption to each block, concatenate the results, and strip PKCS7 padding.

---

## Script

```python
#!/usr/bin/env python3
import json
from pathlib import Path

HERE = Path(__file__).parent


def bytes_to_bits(data: bytes) -> list[int]:
    return [(data[i // 8] >> (7 - (i % 8))) & 1 for i in range(len(data) * 8)]


def bits_to_bytes(bits: list[int]) -> bytes:
    pt = bytearray(16)
    for i in range(128):
        if bits[i]:
            pt[i // 8] |= 1 << (7 - (i % 8))
    return bytes(pt)


def gf2_elimination(A: list[list[int]], b: list[int]) -> list[int]:
    n = len(A)
    aug = [row[:] + [b[i]] for i, row in enumerate(A)]

    for col in range(n):
        pivot = None
        for row in range(col, n):
            if aug[row][col]:
                pivot = row
                break
        if pivot is None:
            raise ValueError(f"Singular at column {col}")
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

    deltas = []
    for pair in basis_pairs:
        ct = bytes.fromhex(pair["ct"])
        deltas.append(bytes(a ^ b for a, b in zip(ct, zero_ct)))

    M = [[0] * 128 for _ in range(128)]
    for j in range(128):
        bits = bytes_to_bits(deltas[j])
        for i in range(128):
            M[i][j] = bits[i]

    plaintext = b""
    for offset in range(0, len(flag_ct), 16):
        block_ct = flag_ct[offset : offset + 16]
        y = bytes(a ^ b for a, b in zip(block_ct, zero_ct))
        x_bits = gf2_elimination(M, bytes_to_bits(y))
        plaintext += bits_to_bytes(x_bits)

    pad_len = plaintext[-1]
    plaintext = plaintext[:-pad_len]
    print(plaintext.decode())


if __name__ == "__main__":
    main()
```

Run it:

```bash
$ python solve.py
grey{iT5_4LL_l1N3R_aLGyBeR?_a1WaY5_HaZ_B1n...}
```

---

## Flag

```
grey{iT5_4LL_l1N3R_aLGyBeR?_a1WaY5_HaZ_B1n...}
```

---

## Takeaways

| Lesson | Explanation |
|--------|-------------|
| **SubBytes is essential** | It is the *only* non-linear component in AES.  Without it, the cipher collapses to an affine map over GF(2)¹²⁸ that is trivially invertible given 128 chosen plaintexts. |
| **Chosen-plaintext attacks on linear ciphers are devastating** | With just 129 encryptions (all-zero + 128 basis vectors), the entire cipher can be reconstructed. |
| **Never remove the non-linearity** | Any substitution–permutation network *must* have a non-linear layer to resist algebraic attacks.  The S-box is not optional. |

The challenge name is a play on "AE-no-S" (AES without S) — and indeed, without the S, it's no longer secure.
