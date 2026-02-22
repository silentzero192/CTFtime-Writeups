# CTF Writeup

**Challenge Name:** Favorite Programming Language  
**Event:** Bearcat CTF 2026  
**Category:** Reversing (Obfuscated interpreter logic)

> The provided snippet (which resembles an R-like language) accepts a 28-character string, transforms each character with alternating bitwise combinations, and compares the result against the hardcoded ciphertext. Reverse the transformation to recover the input that produces the ciphertext.

---

## 1) Overview

The source limits input to a single 28-character string and rejects it unless the post-transformation vector equals `ct = "CA@PC}Wz:~<uR;[_?T;}[XE$%2#|"`. The transformation processes the first 14 bytes via bitwise operations tied to `i` and the last 14 via `(29 - i)`, applying the same pattern every round.

## 2) Key observations

- Every transformation line boils down to the same bitwise formula: `(x | k) & ~(x & k)` where `k` is either `i` or `29-i`.  
- That expression is equivalent to `x ^ k`, so each byte is XOR’d with a known key value (1–14 for the first half, 14–1 for the second).  
- Since the ciphertext is fixed, we can reverse the XOR per position to recover the original input that would survive the validation.

## 3) Reverse engineering recipe

1. Note that the first loop uses key values `1..14`, so the original bytes must be `ct[i] ^ i` for those positions.  
2. The second loop uses `29 - i` for indices 15..28, i.e., values `14..1`, so we XOR those ciphertext bytes with the mirrored key bytes.  
3. Assemble the recovered characters into a single 28-character string and submit it (or just print it) to prove correctness.

## 4) Execution

```bash
python favrt-lang/decryption.py
```

- The Python helper mirrors the discovered XOR keys by building `[1..14] + [14..1]`, XORing each ciphertext byte with the corresponding key, and printing the flag.  
- Running the script yields the flag without needing to interact with the custom interpreter.

## 5) Flag

```
BCCTF{Pr3t7y_5UR3_1tS_C!!1!}
```

## 6) Lessons learned

1. Bitwise expressions that look complicated often reduce to `xor` once you expand them; verifying with a REPL (or quick script) prevents over-analysis.  
2. When challenge code loops over index-dependent keys, you can usually construct the inverse map per position and recover the original string directly.  
3. Writing a small helper script to encode/decode the known ciphertext keeps the process easy to repeat.
