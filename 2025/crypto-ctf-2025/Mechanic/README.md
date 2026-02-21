# CTF Writeup

**Challenge Name:** Mechanic  
**Event:** Crypto CTF 2025  
**Category:** Post-Quantum Cryptography (Implementation Flaw)  

> Mechanic’s “post-quantum” lock is so easy, even Schrödinger’s cat could crack it — alive and dead.

---

## 1) Overview

We are given:

- `flag_22.enc` (final encrypted file)
- `output.raw` (binary data)
- Source code: `mechanic.py`

The challenge claims to use a **post-quantum KEM (MLKEM_1024)**.

At first glance, this looks secure.

But the vulnerability is not in ML-KEM itself —  
it is in how the secret keys are handled.

---

## 2) Encryption Logic Analysis

Key snippet:

```python
m = randint(2 ** 39, 2 ** 40)
B, c = bin(m)[2:], 0

for b in B:
    if b == '1':
        pkey, skey = kem.keygen()
        ct = Path(f'/flag_{c}.enc')
        kry.encrypt(pkey, pt, ct)
        pt = ct
        c += 1
    else:
        pkey, skey = urandom(kem.param_sizes.pk_size), urandom(kem.param_sizes.sk_size)
    f.write(skey)
```

### What Happens

1. A random 40-bit integer `m` is generated.
2. Its binary representation determines behavior bit-by-bit.
3. For each bit:
   - If bit = `1`:  
     - Generate real keypair  
     - Encrypt current file  
   - If bit = `0`:  
     - Generate random fake keys  
     - No encryption

4. **All secret keys (real and fake) are written to `output.raw`.**

---

## 3) Critical Vulnerability

The program writes:

```
f.write(skey)
```

for **every bit**, including valid secret keys.

This means:

> The secret keys used for real encryption layers are fully leaked.

No cryptanalysis is needed.

This is purely an implementation failure.

---

## 4) Understanding the Encryption Layers

If a bit is `1`:

```
flag.png
 → flag_0.enc
   → flag_1.enc
     → ...
       → flag_22.enc
```

Final file given:

```
flag_22.enc
```

This means:

- There were 23 encryption layers
- Therefore, the 40-bit number had 23 bits set to 1

---

## 5) Extracting Secret Keys

Each MLKEM_1024 secret key size:

```
3168 bytes
```

We split `output.raw` into chunks:

```python
sk_size = 3168
total_keys = len(file_data) // sk_size
```

Since keys are written sequentially,
we must reverse the order during decryption
because encryption stacked layers forward.

---

## 6) Decryption Strategy

We attempt decryption layer by layer:

```python
for i in range(40):
    try:
        kry.decrypt_to_file(data[i], ct, pt)
        ct = pt
    except:
        continue
```

Whenever the correct secret key is used:

- Decryption succeeds
- We move to previous layer

Fake keys simply throw exceptions and are ignored.

We continue until reaching:

```
flag.png
```

---

## 7) Why This Works

Because:

- Every real secret key is exposed
- Order of keys is preserved
- We only need to try each key
- Correct ones successfully decrypt

Security failure type:

> Key Material Leakage

Even the strongest post-quantum primitive fails if secret keys are revealed.

---

## 8) What Went Wrong

This design mistake:

```
Writing secret keys to output.raw
```

completely destroys confidentiality.

The cryptosystem itself (MLKEM_1024) is secure.

The implementation is not.

---

## 9) Core Lesson

Post-quantum ≠ secure by default.

Security depends on:

- Key secrecy
- Correct protocol design
- Proper key lifecycle management

Leaking secret keys reduces:

```
IND-CCA secure KEM
```

to:

```
Plain reversible encryption
```

---

## 10) Takeaway

This challenge was not about breaking:

- ML-KEM
- Lattice cryptography
- Post-quantum assumptions

It was about recognizing:

> If secret keys are written to disk, the system is already broken.

Even Schrödinger’s cat could crack it —
because both alive and dead,  
the keys are right there in `output.raw`.
