# CTF Writeup 

**Challenge Name:** Crazy Curves  
**Platform:** Bearcat CTF 2026  
**Category:** Crypto  
**Difficulty:** Medium  

## 1) Goal (What was the task?)
The task was to recover the real shared secret from a custom elliptic-like key exchange implementation and decrypt the ciphertext in `output.txt`.  
Success condition was printing the flag in format `BCCTF{...}`.

## 2) Key Clues (What mattered?)
- The custom point addition law in `crazy_curve.sage` behaves like complex-number multiplication on a translated/scaled circle.
- `privkey = randint(2, 2^128)` gives a strict upper bound on both secret keys.
- `output.txt` contains both public keys plus AES-CBC `iv` and `ciphertext`.
- The AES key is derived as `sha1(str(ss.x)).digest()[:16]`, so recovering shared-secret `x` is enough.
- The used curve is chosen from many candidates, but public keys allow identifying the exact one.

## 3) Plan (Your first logical approach)
- Parse all curves from `crazy_curve.sage`, then detect which curve the provided public keys belong to.
- Convert points to normalized coordinates where the custom group law becomes multiplicative.
- Use subgroup discrete logs on factors of group order (`p+1`) to recover Bob’s private key modulo a large CRT modulus.
- Enumerate remaining key candidates within `[2, 2^128]`, derive AES keys, and stop at valid `BCCTF{...}` plaintext.

## 4) Steps (Clean execution)
1. Action: Parsed `curves` and transcript data (`Alice public key`, `Bob public key`, `iv`, `ciphertext`).  
   Result: Found a unique matching curve: `Daquavious Pork`.  
   Decision: Attack only this curve’s group.

2. Action: Rewrote points as normalized pairs `((x-a)/c, (y-b)/c) mod p`.  
   Result: Group operation became fast pair-multiplication equivalent to complex multiplication mod `p`.  
   Decision: Use multiplicative-group DLP techniques directly.

3. Action: Used partial factor attack on `p+1` with BSGS/Pollard-rho for selected factors and combined residues via CRT.  
   Result: Recovered `b (mod M)` with `M` large enough to leave a small candidate count under the `2^128` bound.  
   Decision: Brute-force only the remaining candidates (thousands, not astronomical).

4. Action: For each candidate `b`, computed shared secret from Alice’s public key, derived AES key, decrypted, and checked padding + `BCCTF{...}` format.  
   Result: One candidate produced valid plaintext flag.  
   Decision: Finalize solver script.

5. Action: Automated everything in `solve.py`.  
   Result: Running one command prints the flag.  
   Decision: Use this as final reproducible solution.

## 5) Solution Summary (What worked and why?)
The core weakness was the mismatch between large group size and small private-key range (`<= 2^128`).  
After mapping the custom curve law to a multiplicative form, I used subgroup discrete logs and CRT to recover Bob’s key modulo a large partial modulus. That left only a small set of possible private keys in the allowed range. Trying those candidates against the AES ciphertext quickly identified the correct shared secret and revealed the flag.

## 6) Flag
`BCCTF{y0U_sp1n_mE_r1gt_r0und}`

## 7) Lessons Learned (make it reusable)
- Custom curve/group definitions are often disguised versions of known algebraic groups.
- Private key bounds can make partial discrete-log recovery enough, even without solving the full DLP.
- If ciphertext validation is available (padding/format), it can prune key candidates very efficiently.
- Always read how the symmetric key is derived; many crypto CTFs hinge on that final conversion.

## 8) Personal Cheat Sheet (optional, but very useful)
- `bash -ic 'act && python3 solve.py'` -> run the final automated solver.
- `p+1` factor + subgroup logs + CRT -> strong first approach when group order is smooth-ish.
- Normalize custom group laws early -> may reveal hidden multiplicative/additive structure.
- Crypto CTF pattern -> parse source + parse transcript + exploit keyspace bounds + validate via decryption.
