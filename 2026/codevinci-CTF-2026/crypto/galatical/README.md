# Galatical - Writeup
**Challenge Name**: `Galatical`
**Platform**: `Codevinci CTF 2026`
**Category**: `Crypto`

## Goal (What was the task?)
Recover the RSA-encrypted flag embedded in `output.txt`, which contains two ciphertexts (`c1`, `c2`), a shuffled set of noisy evaluations of a degree-9 polynomial, and the public modulus/exponent. Success is obtaining a string matching `flag{…}`.

## Key Clues (What mattered?)

- `galatical.py`: Gaussian-style RSA challenge generator with hidden polynomial evaluation.
- Output file: includes `n`, `e`, `deg`, `noise_bits`, `c1`, `c2`, and `(xᵢ, yᵢ, rᵢ)` triples.
- `noise_bits = 16` and `rᵢ` values are RSA-encrypted noise (`rᵢ^17 mod n`).
- `c1 = m^e mod n` and `c2 = f(m)^e mod n` with `f` a degree-9 polynomial.

## Plan (Your first logical approach)

- Recover each noisy `yᵢ` by computing the 17th root of `rᵢ` and subtracting it from `yᵢ` mod `n`.
- Use Lagrange interpolation over the `xᵢ` points to reconstruct `f(x)` modulo `n`.
- Compute the GCD between `f(x)^e − c2` and `x^e − c1` to isolate the factor `x − m`, extract `m`, and decode it to ASCII.

## Steps (Clean execution)

1. Interpreted `output.txt` to pull `n`, `e`, and the noisy points; confirmed `noise_bits = 16`.  
2. Wrote `solve_galatical.py` to compute integer roots of each `rᵢ`, subtract the recovered noise from each `yᵢ`, and collect `(xᵢ, y_corrᵢ)` pairs.  
3. Implemented modular polynomial arithmetic (add/sub/mul/pow/pseudo-remainder) to interpolate `f` (degree 9) via Lagrange and compute `f(x)^e`.  
4. Computed the pseudo-GCD of `f(x)^e − c2` and `x^e − c1` modulo `n`; the resulting linear polynomial revealed `m`.  
5. Converted `m` to bytes to obtain `CodeVinci{...}`.

## Solution Summary (What worked and why?)
The challenge hides the RSA plaintext within a polynomial evaluation. Removing the RSA-encrypted noise allowed recovery of exact `f(x)` values at ten points, so Lagrange interpolation gave the full polynomial. Since `c1` and `c2` are both `e`th powers, computing the modular GCD between `f(x)^e − c2` and `x^e − c1` isolates the shared root `m`. Converting that root back to bytes yields the flag.

## Flag
`CodeVinci{p0lyn0m14l_rs4_l34ks_r00t5_lm4o}`

## Lessons Learned (make it reusable)

- Modular polynomial arithmetic (interpolation, pseudo-remainder, GCD) is useful for linking algebraic relations in RSA challenges.  
- When ciphertexts encode polynomial evaluations, recovering noise (when possible) and recomputing the polynomial is a powerful tool.  
- Always check for small public exponents; GCD on `x^e − c` pairs often reveals shared roots.

8) Personal Cheat Sheet (optional, but very useful)
- Integer nth root (`pow(mid, n)`) → use binary search when no library root is available.  
- Modular Lagrange interpolation → build term-by-term with `poly_mul` and `modinv`.  
- Polynomial pseudo-GCD → helpful when ciphertexts share a root; result can be linear even if inputs have large degree.
