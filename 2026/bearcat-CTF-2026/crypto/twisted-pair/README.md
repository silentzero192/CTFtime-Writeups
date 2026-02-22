# CTF Writeup

**Challenge Name:** Twisted Pair  
**Event:** Bearcat CTF 2026  
**Category:** Cryptography (RSA with leaked φ multiple)

> A “twisted” exponent pair leaks a multiple of φ(n) instead of φ(n) itself. Employ a Miller–Rabin-style search for a non-trivial square root of 1 to factor `n` and decrypt the ciphertext.

---

## 1) Overview

You are given `n`, `e = 65537`, ciphertext `c`, and a pair `(re, rd)` such that `re · rd ≡ 1 mod k·φ(n)`; in other words, the product is a multiple of φ(n) but not necessarily φ(n) itself. The goal is to factor `n` from this leakage and use the true private key to recover the flag.

## 2) Key observations

- `kphi = re * rd - 1` is explicitly computed, so it is a known multiple of φ(n).  
- Factoring multiples of φ(n) can be done by mimicking the Miller–Rabin loop: factor out powers of 2 (`kphi = 2^s * t`) and look for a random base `a` such that successive squarings reveal a non-trivial square root of 1 modulo `n`.  
- Once `x^2 ≡ 1 (mod n)` with `x ≠ ±1` is found, `gcd(x-1, n)` yields a non-trivial factor of `n`, letting us compute `d` and decrypt `c`.

## 3) Attack blueprint

1. Compute `kphi = re * rd - 1` and factor out all powers of 2: `kphi = 2^s * t` with `t` odd.  
2. Loop over random bases `a` in `[2, n-2]`.  
   - Compute `x = pow(a, t, n)` and iterate `j` from `0` to `s-2`: if `x^2 % n == 1` but `x != ±1 mod n`, then `gcd(x-1, n)` yields a factor.  
   - Otherwise square `x` and continue; if one of the squarings yields `n-1`, discard the base and try another.  
3. After finding `p` and `q`, compute `φ = (p-1)(q-1)`, `d = inverse(e, φ)`, then decrypt `m = pow(c, d, n)` and convert to bytes.

## 4) Execution

```bash
cd twisted-pair && python solve.py
```

- The script prints `s = 5`, attempts random bases, and once it finds a non-trivial root of unity, prints the factor pair and flag.  
- If factoring fails (rarely), it falls back to computing `d = inverse(e, kphi)` when `gcd(e, kphi) = 1`, but the Miller–Rabin approach succeeds quickly.

## 5) Result

- Flag: `BCCTF{D0n7_g37_m3_Tw157eD}`
- The ciphertext decrypts cleanly once `n` is factored via `gcd(x-1, n)` derived from the non-trivial square root provided by the leaked `kphi`.

## 6) Lessons learned

1. Multiples of φ(n) leak almost as much information as φ(n) itself when you can do Miller–Rabin style squaring.  
2. Always remove powers of two from the exponent before starting the squaring loop, just like in primality proofs.  
3. If a factoring approach stalls, keep fallback ideas (like `d = inverse(e, kphi)`) handy even when they rarely trigger.
