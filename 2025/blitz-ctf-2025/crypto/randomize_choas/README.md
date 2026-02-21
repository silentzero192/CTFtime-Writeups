# CTF Writeup

**Challenge Name:** Randomize Chaos  
**Platform:** Blitz CTF 2025  
**Category:** Crypto  
**Difficulty:** Medium  
**Time Spent:** ~30 minutes  

---

## 1) Goal (What was the task?)

We were given a custom encryption script `enc.py` and a large file `output.txt` containing many ciphertexts.

The objective was to recover the original flag:

```
Blitz{...}
```

---

## 2) Understanding the Encryption Scheme

From `enc.py`:

```python
import random

flag = b"Blitz{REDACTED}"

def complex_encrypt(flag_bytes, key_bytes):
    result = bytearray()
    for i in range(len(flag_bytes)):
        k = key_bytes[i] % 256
        f = flag_bytes[i]
        r = (f ^ k) & ((~k | f) & 0xFF)
        r = ((r << (k % 8)) | (r >> (8 - (k % 8)))) & 0xFF
        result.append(r)
    return result

with open("output.txt", "w") as f:
    for _ in range(624 * 10):
        key = [random.getrandbits(32) for _ in range(len(flag))]
        ct = complex_encrypt(flag, key)
        f.write(ct.hex() + "\n")
```

---

## 3) Key Observations

### 🔎 1. Encryption is byte-wise

Each flag byte is encrypted independently:

```
r = F(f, k)
```

So we can attack each position separately.

---

### 🔎 2. Keys are random every time

For every encryption:

```python
key = [random.getrandbits(32) ...]
```

And only:

```
k % 256
```

is used.

So effectively:

```
k ∈ {0..255} uniformly random
```

Each ciphertext line is:

```
Same flag + different random 8-bit keys
```

We are given:

```
624 * 10 = 6240 ciphertexts
```

That is a huge statistical sample.

---

## 4) What Is the Weakness?

This is not real cryptography.

This is:

```
cipher_byte = nonlinear_function(flag_byte, random_key_byte)
```

Since:

- Key is uniformly random
- We have thousands of samples
- Flag is constant

👉 Each ciphertext position follows a probability distribution
👉 That distribution depends **only on the flag byte**

This becomes a **statistical fingerprinting attack**.

---

## 5) Attack Strategy

For each byte position:

1. Collect frequency of ciphertext values.
2. For each possible flag byte `f_guess`:
   - Simulate encryption over all `k in [0..255]`
   - Compute theoretical distribution
3. Compare real distribution to simulated one
4. Pick the flag byte that minimizes error

---

## 6) Core Idea in Code

### Single Byte Encryption

```python
def complex_encrypt_byte(f, k):
    k %= 256
    r = (f ^ k) & ((~k | f) & 0xFF)
    r = ((r << (k % 8)) | (r >> (8 - (k % 8)))) & 0xFF
    return r
```

---

### Frequency-Based Recovery

```python
from collections import Counter

def recover_flag_freq(ciphertexts, length):
    flag = bytearray()
    freq_list = [Counter(ct[i] for ct in ciphertexts) for i in range(length)]

    for freq in freq_list:
        best_f, best_score = 0, float("inf")
        total = sum(freq.values())

        for f_guess in range(256):
            sim = Counter(complex_encrypt_byte(f_guess, k) for k in range(256))
            for k in sim:
                sim[k] /= 256

            score = sum((freq[c] / total - sim.get(c, 0)) ** 2 for c in freq)
            if score < best_score:
                best_score, best_f = score, f_guess

        flag.append(best_f)
    return flag
```

---

### Loading Ciphertexts

```python
with open("output.txt") as f:
    ciphertexts = [bytearray.fromhex(line.strip()) for line in f]

flag = recover_flag_freq(ciphertexts, len(ciphertexts[0]))
print("Recovered flag:", flag.decode())
```

---

## 7) Why This Works

For a fixed flag byte `f`:

```
C = F(f, K)
```

where `K` is uniform in `[0..255]`.

Thus:

```
Distribution(C | f)
```

is fixed and deterministic.

Given thousands of samples:

```
Observed distribution ≈ True distribution
```

So we reverse the process statistically.

This is essentially:

- Not encryption
- Not secure randomness
- Just a deterministic function with random input

And enough samples destroys it.

---

## 8) Final Flag

```
Blitz{RaNDm_KEY_GENeRateD_By_Zwique}
```

---

## 9) Why the Scheme Is Broken

- Each position is independent
- No chaining (no diffusion)
- Key is fully random and independent per sample
- Massive number of samples given
- Function is reversible statistically

This is a textbook example of:

> Randomness ≠ Security

---

## 10) Key Takeaways

- If you encrypt the same secret many times with independent random keys → leakage occurs.
- Statistical attacks are extremely powerful.
- Large sample size can break nonlinear functions.
- True cryptosystems avoid deterministic structure per byte.

---

## 11) Attack Summary

| Property | Impact |
|-----------|---------|
| Same flag reused | Enables aggregation |
| Independent byte encryption | Position-wise attack |
| Random uniform keys | Predictable distribution |
| 6240 samples | Strong statistical certainty |

---

## 12) Final Thoughts

This challenge demonstrates that:

Even chaotic-looking bitwise operations are not secure if:

- They lack diffusion
- They lack proper cryptographic design
- They leak repeated encryptions

Randomness alone does not make a cipher secure.

---
