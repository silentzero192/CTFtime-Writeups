# CTF Writeup

**Challenge Name:** Tropped  
**Event:** Bearcat CTF 2026  
**Category:** Cryptography (Tropical matrix encryption)

> The ciphertext dumps rows, columns, and encrypted characters produced by tropical (min,+) multiplication. Reverse the residuation to recover the shared secret.

---

## 1) Overview

`output.txt` logs a 64×64 matrix `M` plus one JSON entry per encrypted character containing a row vector `aM`, a column vector `Mb`, and the XORed ciphertext byte `enc_char`. The generator uses `a ⊗ M ⊗ b` (tropical multiplication) and then creates the ciphertext byte via `(aMb % 32) XOR enc_char`. Our job is to invert these steps to reveal the plaintext flag.

## 2) Tropical structure insights

- Tropical multiplication uses `min` for addition and `+` for multiplication: `(A ⊗ B)[i][j] = min_k(A[i][k] + B[k][j])`. The generator stores `aM = a ⊗ M` and `Mb = M ⊗ b`.  
- Decrypting a character requires recovering `b` from `Mb` because only that combined information ties to the secret. Tropical residuation gives the maximum `b` satisfying `M ⊗ b ≤ Mb` element-wise, and that value matches the original `aMb`.  
- Once `b` is known, `aMb = min_k(aM[k] + b[k])`, and the plaintext byte becomes `chr((aMb % 32) ^ ord(enc_char))`.

## 3) Inversion recipe

1. Parse `M` from the first line of `output.txt`.  
2. For each ciphertext entry: compute `b_lower[k] = max_i(Mb[i] - M[i][k])`; this is the tropical lower bound giving the exact column vector used to compute `Mb`.  
3. Compute the shared secret `aMb = min_k(aM[k] + b_lower[k])`.  
4. Invert the modular/XOR step: `pt_char = chr((aMb % 32) ^ ord(enc_char))` and append to the flag string.

## 4) Execution

```bash
cd tropped && python solve.py
```

- The solver reads all JSON lines, iterates through each encrypted character, applies the residuation formula, and decrypts the resulting plaintext.  
- The process produces a printable flag without any brute forcing because every computation mirrors the generator’s deterministic flow.

## 5) Result

- Flag: `BCCTF{1_h4T3_M7_Tr0p93D_4Hh_CRyp705ysT3m}`
- The decrypted text emerges precisely because `aM` and `Mb` together leak the value needed to reconstruct `a ⊗ M ⊗ b`.

## 6) Lessons learned

1. Tropical algebra cryptosystems can be inverted by residuation if you have both the row and column products.  
2. Storing partial results (like `aM` and `Mb`) without zero-knowledge masking leaks the shared secret.  
3. When the final cipher includes a simple modular XOR, reversing it is as simple as applying XOR again, then unwrapping any modular behavior.
