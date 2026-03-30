# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

Challenge Name: chill  
Platform: VolgaCTF 2026  
Category: Crypto  
Difficulty: Medium  
Time spent: ~15 minutes

## 1) Goal (What was the task?)
The challenge gave us a Sage script and an output file, then asked us to recover a secret key. In this case, the private key was the flag itself, so success meant reconstructing that key and reading the final `VolgaCTF{...}` string.

## 2) Key Clues (What mattered?)
- `main.sage` implements a DSA-like signature system.
- `output` contains `Q`, `P`, `G`, `Y`, and two signatures `(R1, S1)` and `(R2, S2)`.
- The nonce generator is weak:
  `seed += q_ring(K.random_element())`
- `K = IntegerModRing(2 ^ 22)` means the difference between consecutive nonces is only a 22-bit value.
- The script signs exactly two known messages: `message1` and `message2`.
- The private key is set as `int.from_bytes(FLAG, 'big')`, so recovering the key directly recovers the flag.

## 3) Plan (Your first logical approach)
- Read the Sage source first to understand whether the weakness was in parameter generation, key generation, or signing.
- Focus on the nonce generator, because DSA is usually broken by reused or predictable nonces.
- Use the two known signatures to build modular equations involving the same private key and closely related nonces.
- Brute-force the small 22-bit nonce difference and verify candidates against the public key `Y`.

## 4) Steps (Clean execution)
1. Action: Read `main.sage` and identify how the signature scheme works.  
   Result: The signing equation is standard DSA-style:
   `s = k^(-1) * (m + x*r) mod q`.  
   Decision: This means weak nonces can expose the private key `x`.

2. Action: Inspect the nonce generator.  
   Result: The first nonce is random, but the next nonce is computed by adding a random value from a 22-bit ring. So:
   `k2 = k1 + d mod q`, where `0 <= d < 2^22`.  
   Decision: That small relation is brute-forceable.

3. Action: Write the two signature equations:
   `s1*k1 = m1 + x*r1 mod q`
   `s2*k2 = m2 + x*r2 mod q`  
   Result: Substitute `k2 = k1 + d` and eliminate `x` to express `k1` in terms of `d`.  
   Decision: Loop over all `d` in `0..2^22-1`, recover candidate `k1`, then candidate `x`.

4. Action: For each candidate `x`, verify it using the public key:
   `g^x mod p == y`.  
   Result: Only one candidate matched the public key.  
   Decision: Convert that integer back to bytes to recover the flag string.

5. Action: Sanity-check the recovered key.  
   Result: The decoded bytes formed a valid flag, and the recovered nonce gap was `3517569`, which is indeed less than `2^22`.  
   Decision: Accept the solution as correct.

## 5) Solution Summary (What worked and why?)
The core weakness was not in DSA itself, but in the nonce generation. The challenge used two signatures whose nonces differed by only a small 22-bit value. Since DSA signatures depend directly on the nonce, that relation let us combine the two equations and brute-force the missing difference. Once the correct difference was found, the private key followed immediately, and because the script stored the flag directly as the private key, converting that integer back into bytes revealed the flag.

## 6) Flag
`VolgaCTF{n0_l4z1n355_1n_cryp70gr4phy}`

## 7) Lessons Learned (make it reusable)
- In DSA-style systems, always inspect nonce generation before anything else.
- Even if a nonce is not reused exactly, a small relation between two nonces can still be fatal.
- When the challenge gives both source code and signature output, combine them instead of treating them separately.
- Public key verification is a clean way to confirm the correct private key candidate during brute-force recovery.

## 8) Personal Cheat Sheet (optional, but very useful)
- `main.sage` -> read the implementation before attempting algebra.
- `output` -> extract public parameters, messages, and signatures.
- DSA pattern -> check for nonce reuse, predictable increments, small bias, or leaked bits.
- Verification pattern -> after recovering a private key candidate, test whether `g^x mod p == y`.
