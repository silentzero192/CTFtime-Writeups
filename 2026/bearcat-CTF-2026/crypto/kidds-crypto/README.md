# CTF Writeup

**Challenge Name:** kidds-crypto  
**Event:** Bearcat CTF 2026  
**Category:** Cryptography (Low-exponent RSA with known small factors)

> Leverage the exposed small-factors of the modulus to reverse low-exponent RSA by combining modular cube roots with CRT.

---

## 1) Overview

Given `n`, `e=3`, and ciphertext `c`, the solver already ships a list of small prime factors of `n`. The goal is to recover the plaintext flag encoded inside the RSA message.

## 2) Core observations

- The challenge supplies `fast_factors` that cover all primes dividing `n`, so factoring is trivial once those primes are confirmed.  
- Because `e=3` is so small, we can solve for the plaintext by computing modular cube roots of `c` modulo each factor and combining the results via CRT.  
- The plaintext begins with the flag prefix `BCCTF{`, so we can stop as soon as we see that pattern after reconstruction.

## 3) Attack strategy

1. For every prime in `fast_factors`, compute all values `r` such that `r^3 ≡ c (mod p)`; SymPy’s `nthroot_mod` returns the complete root set when the modulus is prime.  
2. Build CRT constants `C_p = (n/p) * inv(n/p, p)` so that the weighted sum `∑ r_p * C_p mod n` yields a candidate plaintext.  
3. Iterate over Cartesian products of the modular roots until the resulting plaintext bytes contain `BCCTF{`; this indicates the correct combination.

## 4) Execution

```bash
python kidds-crypto/solve.py
```

- The script computes the cube roots for each prime and precomputes CRT weights.  
- It enumerates combinations while printing progress every 100k iterations.  
- Once a candidate plaintext contains `BCCTF{`, it prints `FOUND FLAG` and exits.

## 5) Result

- `BCCTF{y0U_h4V3_g0T_70_b3_K1DD1n9_Me}`
- Because the plaintext was reconstructed directly from the correct combination of roots, there was no need for further guesswork.

## 6) Lessons learned

1. When RSA uses a tiny exponent like 3, computing modular roots modulo the prime factors and recombining with CRT is efficient.  
2. Knowing the flag format lets you short-circuit brute-force searches over CRT combinations.  
3. Precomputing CRT constants (`N_p` and its inverse) prevents redundant work during enumeration.
