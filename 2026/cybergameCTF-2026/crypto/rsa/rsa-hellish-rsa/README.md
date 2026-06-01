# Hellish RSA - Writeup

**Challenge Name:** `Hellish RSA`  
**Platform:** `CyberGame CTF 2026`  
**Category:** `Crypto`  

## 1) Goal (What was the task?)
The challenge provided RSA-like values `n`, `e`, `c` and a generator script, then asked us to recover a flag in format `SK-CERT{...}`.  
Success means extracting the exact flag string from the given challenge files.

## 2) Key Clues (What mattered?)
- Prompt/title clue: "This RSA crypto task comes straight from HELL, or does it ?"
- Files: `hell-rsa.py` and `data.txt`
- In source: `n = pow(first_devil, second_devil)` (not normal `p*q`)
- In source: `m = (1 + demon * first_devil) % n` so plaintext is in a special subgroup
- In output: very large `n`, `e`, `c` and no direct plaintext
- Algebraic clue from data: `gcd(c - 1, n)` immediately gives a large prime factor

## 3) Plan (Your first logical approach)
- Parse the generator carefully to understand how `n`, `e`, and `m` were built.
- Check if `n` is composite in a special way (not standard RSA modulus).
- Use number-theory structure (`gcd(c-1, n)`) to recover hidden modulus parameters.
- Convert encryption equation into a solvable form and extract the flag bytes.

## 4) Steps (Clean execution)
1. Action: Read `hell-rsa.py` and `data.txt`.  
   Result: Saw non-standard setup: modulus is a prime power, and `m` lies in `1 + pZ`.  
   Decision: Stop treating it like classic RSA with `phi = (p-1)(q-1)`.

2. Action: Compute `p = gcd(c - 1, n)`.  
   Result: Recovered a 2048-bit prime `p` and verified `n = p^4`.  
   Decision: Work inside modulo `p^4` structure.

3. Action: Rewrite equation as `c = e^x (mod p^4)` where `x` is the hidden message integer.  
   Result: Both `e` and `c` are in subgroup `1 + pZ/p^4Z`.  
   Decision: Use p-adic logarithm to linearize exponentiation.

4. Action: Apply truncated p-adic log:
   - `log(1+t) = t - t^2/2 + t^3/3 (mod p^4)`
   - Compute `Le = log(e)`, `Lc = log(c)`
   - Solve `x = (Lc/p) * (Le/p)^(-1) mod p^3`  
   Result: Recovered plaintext integer `x`, converted to bytes, extracted flag with regex.  
   Decision: Implemented full automation in `solution.py`.

5. Action: Run solver:
   ```bash
   python3 solution.py
   ```
   Result: Printed the final flag.

## 5) Solution Summary (What worked and why?)
The challenge looked like RSA, but `n` was not `p*q`; it was `p^4`, and ciphertext/plaintext were intentionally placed in the multiplicative subgroup `1 + pZ`. In that subgroup, exponentiation can be transformed into multiplication using a p-adic logarithm. After recovering `p` via `gcd(c-1, n)`, I used the truncated p-adic log series modulo `p^4`, solved a linear congruence for the hidden exponent/message, converted it to bytes, and extracted the embedded `SK-CERT{...}` flag.

## 6) Flag
`SK-CERT{p-4d1c_l0g4r17hm5_rul3_t0d4y_1n_5ubgr0up5}`

## 7) Lessons Learned (make it reusable)
- "RSA-looking" challenges may hide non-standard moduli like `p^k` instead of `p*q`.
- Always test quick invariants early: `gcd(c-1, n)`, perfect-power checks, bit lengths.
- Subgroup structure (`1 + pZ`) can make hard exponent equations linearizable with p-adic logs.
- Avoid forcing textbook RSA decryption when challenge code clearly deviates from textbook setup.

## 8) Personal Cheat Sheet (optional, but very useful)
- `gcd(c-1, n)` -> often leaks factors when values are crafted near `1 mod p`.
- Perfect-power test (`isqrt`, `iroot`) -> detects `n = p^k` quickly.
- p-adic log trick -> useful for equations of form `g^x = h (mod p^k)` with `g,h in 1+pZ`.
- `python3 solution.py` -> one-shot recovery and flag extraction for this challenge.
