# CTF Writeup

**Challenge Name:** Missing Piece  
**Event:** Bearcat CTF 2026  
**Category:** Reversing (ELF byte-level transformation)

> The ELF binary performs a custom byte-wise transformation on the hardcoded seed string `"./devilishFruitPWD=/tmp/gogear5ONE_PIECE=IS_REAL"` using a 48-byte delta table, and prints the result if it matches the expected flag format. Reversing the transformation recovers the flag.

---

## 1) Overview

Disassembling the ELF reveals a data segment containing `delta[]` and the seed string. The transformation walks through each byte, XORs against `delta`, and then runs a series of 1-bit left rotations with tweaks that depend on the previous byte’s LSB. The goal is to compute the final flag string produced by those operations.

## 2) Key observations

- The binary loads the initial string (length 48) and, for every index `i`, sets `v2 = delta[i] ^ data[i]`.  
- Starting from `i=1`, it rotates `v2` left by one bit three times, XORs the previous byte’s LSB into it between rotations, and applies one final rotation before storing it back.  
- Since both the delta table and the seed string are embedded in the ELF, we can replicate the transformation in Python to output the final string the binary would print.

## 3) Reverse engineering recipe

1. Copy the seed string and `delta` table from the binary’s data section—these pad the XOR and the rotation inputs.  
2. Simulate the transformation: for each index, XOR with `delta[i]`, perform three `rol1` steps (each followed by XOR with the previous byte’s lowest bit), and then one final `rol1`.  
3. Convert the resulting bytes back to ASCII; this is the flag.

## 4) Execution

```bash
python missing-piece/decrypt.py
```

- The decryption script mirrors the ELF logic: it iterates over all 48 bytes, applies the XOR and rotation pipeline, and prints the transformed string.  
- Since all constants are hardcoded, no additional input is required.

## 5) Flag

```
BCCTF{I_gU3S5_7hAt_Wh1t3BeArD_6uY_W45_TRu7h1n6!}
```

## 6) Lessons learned

1. When an ELF contains both a delta table and a plaintext seed, re-implementing the algorithm in Python is faster than trying to patch the binary.  
2. Custom rotations usually correspond to simple bit shifts—logging intermediate values can confirm you reconstructed the same pipeline as the binary.  
3. Keeping a helper script handy makes repeating the solve easy if you need to test variations or explain your process.
