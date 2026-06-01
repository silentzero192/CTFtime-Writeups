# RSA Prime Classes - Writeup

**Challenge Name:** `rsa prime classes`  
**Platform:** `CyberGame CTF 2026`  
**Category:** `Crypto`

## 1) Goal (What was the task?)

The task was to recover the plaintext flag encrypted with RSA.  
Success condition was printing a valid flag in the format `SK-CERT{...}`.

## 2) Key Clues (What mattered?)
- `e = 3` (small public exponent)
- Custom function `isNiceNumber(m)` in `main.py`
- `isNiceNumber` forced `m` to be divisible by at least one value from each class:
  - `smallClass`
  - `middleClass`
  - `bigClass`
- Ciphertext parameters were provided in `output.txt`: `c`, `n`, `e`
- Flag format was known: starts with `SK-CERT{` and ends with `}`

## 3) Plan (Your first logical approach)
- Read `main.py` and identify what constraints are imposed on plaintext `m`.
- Use the RSA equation with `e=3`: `m^3 = c + k*n` for some integer `k`.
- Use known flag prefix/suffix to bound candidate message lengths and therefore bound `k`.
- Use class-divisibility constraints to derive modular equations for `k`, then test exact cube candidates.

## 4) Steps (Clean execution)
1. Action: Parsed `smallClass`, `middleClass`, `bigClass` from `main.py` and `c,n,e` from `output.txt`.  
   Result: Confirmed standard RSA encryption with `e=3` and a strong structural leak on plaintext.  
   Decision: Turn the leak into arithmetic constraints.
2. Action: Rewrote RSA relation as `m^3 = c + k*n`.  
   Result: Instead of factoring `n`, the problem became finding valid `k` such that `c + k*n` is a perfect cube.  
   Decision: Reduce `k` search space using known flag shape and divisibility.
3. Action: Used `SK-CERT{...}` format to build min/max message for each length and computed `[k_min, k_max]`.  
   Result: Only a few lengths were plausible; this removed huge parts of the search space.  
   Decision: Add congruence filters from the class constraints.
4. Action: If `m` is divisible by a class factor `d`, then `d^3 | m^3`, so:
   `c + k*n ≡ 0 (mod d^3)` => `k ≡ -c * n^{-1} (mod d^3)`.  
   Used `d = lcm(middlePrime, bigPrime)` to make modulus large and candidate count tiny.  
   Result: Very few `k` values needed exact-cube checking (`gmpy2.iroot`).  
   Decision: Validate candidates against prefix/suffix and all class conditions.

## 5) Solution Summary (What worked and why?)
The challenge leaked plaintext structure through `isNiceNumber(m)`. That made `m` guaranteed to share factors from specific classes, and with `e=3` this directly produced modular constraints on `k` in `m^3 = c + k*n`. Combined with the known flag format (`SK-CERT{...}`), the valid `k` range became narrow enough to test quickly. Exact cube checks then revealed the unique valid plaintext and flag.

## 6) Flag
`SK-CERT{l34k3d_57ruc7ur3_g1v35_6w6y_7h3_50lu710n}`

## 7) Lessons Learned (make it reusable)
- RSA can fail even without factoring `n` when plaintext has leaked arithmetic structure.
- For `e=3`, always consider `m^3 = c + k*n` and search over constrained `k`.
- Known flag prefix/suffix is powerful for bounding plaintext and auxiliary variables.
- Custom validation functions in challenge code often leak exactly what you need.

## 8) Personal Cheat Sheet (optional, but very useful)
- `m^e = c + k*n` -> useful when `e` is small and message has structure.
- `gmpy2.iroot(x, 3)` -> fast exact cube test.
- If `d | m`, then `d^e | m^e`; convert to congruence on `k`.
- Crypto CTF checklist:
  - Read source first
  - Identify algebraic constraints on plaintext
  - Use format leaks (`flag{}`, `SK-CERT{}`) to reduce search space
