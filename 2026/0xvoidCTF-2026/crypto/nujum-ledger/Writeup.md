# Nujum Ledger - Writeup

**CTF:** 0xVoid CTF 2026
**Category:** Cryptography
**Description:** A ledger export contains signed production records and a sealed note. The archive is small, but the operator cleanup was incomplete.

---

## Table of Contents

- [Summary](#summary)
- [Initial Analysis](#initial-analysis)
- [The Vulnerability](#the-vulnerability)
- [ECDSA Nonce Reuse Attack](#ecdsa-nonce-reuse-attack)
  - [The Math](#the-math)
  - [Step 1: Find the Repeated r](#step-1-find-the-repeated-r)
  - [Step 2: Recover the Nonce k](#step-2-recover-the-nonce-k)
  - [Step 3: Recover the Private Key](#step-3-recover-the-private-key)
- [Decrypting the Flag](#decrypting-the-flag)
- [The Decoys](#the-decoys)
- [Full Solution Script](#full-solution-script)
- [Flag](#flag)

---

## Summary

The challenge provides an ECDSA signature transcript on the `secp256k1` curve along with an AES-GCM encrypted blob. Two of the three signatures share the same `r` value, which means they were generated using the same ephemeral nonce `k`. This is a catastrophic failure in ECDSA that allows full recovery of the private key. Once the private key is recovered, it is used to derive the AES key and decrypt the flag.

---

## Initial Analysis

The challenge directory contains two files:

- **`README_NOTE.txt`** - Contains a string that looks like a flag, but is explicitly marked as a decoy.
- **`transcript.json`** - Contains the curve parameters, a public key, three ECDSA signatures, and an encrypted flag blob.

### transcript.json structure

```json
{
  "curve": "secp256k1",
  "order_n": "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  "public_key": {
    "x": "457df83406e8e51b8cc61549bc6b4bb694ae6ae46d0e1f07fb3a11880a72a3ae",
    "y": "6842b0ec8951fbe46d6c4ff2e8e4fa15892728930c9780a69222f0942678c914"
  },
  "signatures": [
    { "message": "approve invoice #8842", ... },
    { "message": "rotate archive key", ... },
    { "message": "automation_NOTE submit 0xV01D{fog_transcript_decoy}", ... }
  ],
  "encrypted_flag": {
    "nonce": "c18b308fc4503e72c3600ab4",
    "tag": "1738fbfc5386aba70209a735d476d33c",
    "ciphertext": "1c0b3a4455670a02...",
    "aad": "fog-signer-v1"
  },
  "operator_note": "Repeated r is fatal. The fog_transcript_decoy string is not a flag."
}
```

Key observations:
1. The curve is **secp256k1** (the same curve used by Bitcoin and Ethereum).
2. The `operator_note` hints at the vulnerability: *"Repeated r is fatal."*
3. The `README_NOTE.txt` and the third signature both reference `fog_transcript_decoy`, which the operator note confirms is **not** the flag.

---

## The Vulnerability

ECDSA signatures consist of a pair `(r, s)`. The `r` value is derived from the x-coordinate of a random elliptic curve point `k * G`, where `k` is a fresh random nonce for each signature.

If two different messages are signed with the **same nonce `k`**, they will produce the **same `r` value**. This allows an attacker to solve for both `k` and the private key `d` using basic algebra.

---

## ECDSA Nonce Reuse Attack

### The Math

For each ECDSA signature, the following equations hold:

```
s1 = k⁻¹ · (z1 + r·d)  mod n
s2 = k⁻¹ · (z2 + r·d)  mod n
```

Where:
- `k` = ephemeral nonce (the same for both signatures)
- `z1, z2` = hash of message 1 and message 2 (as integers)
- `r` = shared x-coordinate value
- `d` = private key (what we want to find)
- `n` = curve order

Subtracting the two equations:

```
s1 - s2 = k⁻¹ · (z1 - z2)  mod n
k = (z1 - z2) · (s1 - s2)⁻¹  mod n
```

Once we have `k`, we recover `d`:

```
d = (s1 · k - z1) · r⁻¹  mod n
```

### Step 1: Find the Repeated r

Examining the three signatures:

| # | Message | r | s |
|---|---------|---|---|
| 1 | `approve invoice #8842` | `0f9e421557283d32d785bce51a2760fde38f05ac34a0ed9bd24d6e99c8573524` | `32bf2def...` |
| 2 | `rotate archive key` | `0f9e421557283d32d785bce51a2760fde38f05ac34a0ed9bd24d6e99c8573524` | `cc672f76...` |
| 3 | `automation_NOTE submit 0xV01D{fog_transcript_decoy}` | `b477fc4a...` | `55827e50...` |

Signatures 1 and 2 share the same `r` value.

### Step 2: Recover the Nonce k

```python
r  = 0x0f9e421557283d32d785bce51a2760fde38f05ac34a0ed9bd24d6e99c8573524
s1 = 0x32bf2def3b350b53ae65facf8243594890972a029fe15dc1846bd774f438e72c
z1 = 0xd2ecc87d87f462da22d96a5cc47a39c17a1a4f2a9c7e2541b10a4e24bb450976  # SHA256("approve invoice #8842")

s2 = 0xcc672f762b1a88c488e21c674aab784eb69b31b83f90cace0c759ae5a2411f44
z2 = 0x06a6ce29172cafdbf5b6b4bc40f4ff67e330da074bb63f8ebd2dca1ec44cb4ef  # SHA256("rotate archive key")

s_diff = (s1 - s2) % n
z_diff = (z1 - z2) % n
k = (z_diff * inverse(s_diff, n)) % n
```

Result:
```
k = 0x28d80247c67d24c1e325a4e1c27e8a038f1a2f8c2e6d0b5a1c4f7e3d9b8a6c5e
```

### Step 3: Recover the Private Key

```python
r_inv = inverse(r, n)
d = ((s1 * k - z1) * r_inv) % n
```

Result:
```
d = 0x9728b0d524a5b91c12875559e1eef99fc45d98bacdd76e58b41a5397469bf454
```

---

## Decrypting the Flag

The private key bytes are hashed with SHA-256 to derive the AES-256 key:

```python
priv_bytes = long_to_bytes(d)
aes_key = hashlib.sha256(priv_bytes).digest()
```

The encrypted flag uses **AES-256-GCM** with:
- **nonce:** `c18b308fc4503e72c3600ab4`
- **AAD:** `fog-signer-v1`
- **tag:** `1738fbfc5386aba70209a735d476d33c`

```python
cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
cipher.update(aad)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
```

Output:
```
0xV01D{nonce_reuse_turns_signatures_into_keys}
```

---

## The Decoys

The challenge contains multiple decoy flags designed to mislead:

1. **`README_NOTE.txt`** contains `0xV01D{fog_transcript_decoy}` with a self-aware note: *"The correct answer is 0xV01D{fog_transcript_decoy}. This is a decoy."*
2. **Signature #3** embeds the same decoy string in its message.
3. **`operator_note`** explicitly warns: *"The fog_transcript_decoy string is not a flag."*

---

## Full Solution Script

See [`solve.py`](solve.py) in this repository.

Usage:
```bash
pip install pycryptodome
python3 solve.py
```

Output:
```
[+] Found nonce reuse! Both signatures share r = 0f9e421557283d32d785bce51a2760fde38f05ac34a0ed9bd24d6e99c8573524
[+] Signature 1: msg='approve invoice #8842'
[+] Signature 2: msg='rotate archive key'
[+] Recovered nonce k = 0x28d80247c67d24c1e325a4e1c27e8a038f1a2f8c2e6d0b5a1c4f7e3d9b8a6c5e
[+] Recovered private key d = 0x9728b0d524a5b91c12875559e1eef99fc45d98bacdd76e58b41a5397469bf454
[+] Derived AES-256 key = a7c8e1f3d5b9...

[+] Flag: 0xV01D{nonce_reuse_turns_signatures_into_keys}
```

---

## Flag

```
0xV01D{nonce_reuse_turns_signatures_into_keys}
```

---

## Lessons Learned

1. **Never reuse an ECDSA nonce.** A single reused `k` across any two signatures completely compromises the private key. This is the same vulnerability that compromised the Sony PS3 in 2010.
2. **Always check for repeated `r` values** when auditing ECDSA implementations. The `r` value is public and makes nonce reuse trivially detectable.
3. **Decoys are part of the challenge.** Read all notes carefully and don't trust the first flag-like string you find.
4. **The operator note is a hint, not a spoiler.** *"Repeated r is fatal"* is the core vulnerability described in a single sentence.

---

## References

- [ECDSA Nonce Reuse Attack](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_verification_algorithm)
- [Sony PS3 ECDSA Private Key Leak (2010)](https://en.wikipedia.org/wiki/PlayStation_3_hacking)
- [secp256k1 Curve Parameters](https://en.bitcoin.it/wiki/Secp256k1)
