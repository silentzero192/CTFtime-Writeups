# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

**Challenge Name:** gfprng  
**Platform:** VolgaCTF 2026  
**Category:** Crypto  
**Difficulty:** Easy  
**Time spent:** 10 minutes

## 1) Goal (What was the task?)
The challenge gives us a Sage script and an encrypted file called `encrypted_flag`. The objective is to understand the custom PRNG, decrypt the hidden `flag.png`, and recover the final flag in the format `VolgaCTF{...}`.

## 2) Key Clues (What mattered?)
- The script uses `GF(2^8)`, a finite field with 256 elements.
- The PRNG starts from a random field element and repeatedly does `seed *= seed`.
- The plaintext being encrypted is a PNG file: `flag.png`.
- The output is XOR encryption, so recovering the keystream is enough to decrypt everything.
- PNG files always start with the known 8-byte magic header: `89 50 4E 47 0D 0A 1A 0A`.

## 3) Plan (Your first logical approach)
- Read the Sage code first to understand how the keystream is generated.
- Check whether repeated squaring in `GF(2^8)` creates a short cycle.
- Use the known PNG header to recover the first keystream bytes.
- Repeat that keystream over the ciphertext and see whether it produces a valid PNG.

## 4) Steps (Clean execution)
1. **Read the challenge code**
   - Action: Opened `main.sage` and followed the `encrypt()` logic.
   - Result: Each plaintext byte is XORed with bytes from `get_random_byte(K)`.
   - Decision: The real target is the PRNG, not PNG parsing or brute force.

2. **Analyze the PRNG**
   - Action: Looked at `seed *= seed` inside `GF(2^8)`.
   - Result: In characteristic-2 fields, squaring is the Frobenius map. In `GF(2^8)`, applying it 8 times returns to the starting value, so the keystream repeats every 8 bytes.
   - Decision: Recover only the first 8 keystream bytes, then repeat them.

3. **Recover the keystream from the PNG signature**
   - Action: XORed the first 8 ciphertext bytes with the known PNG header.
   - Result: The keystream was:

```text
3a b2 f4 35 e7 99 ee d8
```

   - Decision: Use this 8-byte keystream cyclically for the full file.

4. **Decrypt the ciphertext**
   - Action: XORed every ciphertext byte with `keystream[i % 8]`.
   - Result: The output became a valid PNG image.
   - Decision: Open the image and read the text inside it.

5. **Read the recovered image**
   - Action: Viewed the decrypted PNG.
   - Result: The image directly contained the flag text.
   - Decision: Record the final flag.

## 5) Solution Summary (What worked and why?)
The PRNG looked unusual, but its weakness was actually simple: it repeatedly squared an element inside `GF(2^8)`. In this field, repeated squaring is highly structured and cycles after 8 steps, so the keystream was only 8 bytes long. Since the encrypted file was a PNG, the known file signature gave me those 8 keystream bytes immediately. After that, decrypting the whole file was just a repeating XOR, which revealed the flag image.

## 6) Flag
`VolgaCTF{1f_y0u_g4z3_l0ng_1n70_4n_4lg3br4_7h3_4lg3br4_g4z35_b4ck_1nt0_y0u}`

## 7) Lessons Learned (make it reusable)
- If a stream cipher encrypts a known file type, always test for a known-header XOR recovery.
- In finite field challenges, repeated squaring often means Frobenius behavior, so check the cycle length.
- Reading the source first can save a lot of unnecessary brute force.
- When a pattern looks “random,” inspect whether it is actually a very small repeating state.

## 8) Personal Cheat Sheet (optional, but very useful)
- `xxd encrypted_flag` -> quick hex inspection for repeated structure.
- `file recovered.png` -> confirm whether decryption produced a valid file.
- PNG magic bytes -> `89 50 4E 47 0D 0A 1A 0A`
- Pattern to remember -> XOR + known file header + short-cycle PRNG usually means easy keystream recovery.

