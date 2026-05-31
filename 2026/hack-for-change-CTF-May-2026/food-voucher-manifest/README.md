# Food Voucher Manifest — Writeup

**Challenge**: Food Voucher Manifest  
**Category**: Cryptography / ECB Oracle  
**Flag**: `SDG{...}` (obtained by submitting the recovered audit_secret)

---

## Overview

The Food Voucher Manifest service encrypts delivery notes with AES-128-ECB before disbursal. For integrity, the regional `audit_secret` is appended to every note before encryption. The cryptographer who designed this insisted ECB was "fine because the keys are random."

We are given an oracle that returns the ECB encryption of `(our_input || audit_secret)`. Because ECB encrypts each 16-byte block independently, identical plaintext blocks produce identical ciphertext blocks — enabling a byte-at-a-time chosen-plaintext attack to recover the secret.

```
API endpoint:
https://hackforachangeruntime.vercel.app/api/food-voucher-manifest?seed=3159ba4686adaf03ad9bcd4313ad7360b56110be9156865c9623a36d113d8b04

POST ?action=manifest  {"note_hex": "<hex bytes>"}
→ {"cipher_hex": "<hex ciphertext of (note || audit_secret)>"}
```

---

## Step 1 — Determine the Secret Length

First we probe the oracle to find how long the secret is.

```python
import requests

def encrypt(hex_data):
    r = requests.post(f"{BASE}?seed={SEED}&action=manifest",
                      json={"note_hex": hex_data})
    return r.json()["cipher_hex"]
```

| Padding length | Ciphertext length | Blocks |
|---|---|---|
| 0 | 48 bytes | 3 |
| 1–15 | 48 bytes | 3 |
| 16 | 64 bytes | 4 |

The block boundary is crossed at 16 bytes of padding, meaning:

```
secret_len + 15 ≤ 48    and    secret_len + 16 > 48
→  secret_len = 33 bytes
```

The last byte is PKCS#7 padding (0x01) so the actual secret is **32 bytes**.

---

## Step 2 — ECB Byte-at-a-Time Oracle

### How ECB works

AES-ECB splits the plaintext into 16-byte blocks and encrypts each independently:

```
plaintext:  [block 0 (16 B)] [block 1 (16 B)] [block 2 (16 B)] ...
ciphertext: [CT0]             [CT1]             [CT2]             ...
```

If two plaintext blocks are identical, their ciphertext blocks will be identical too.

### Attack strategy

To recover byte at position `pos` of the secret:

1. **Align the unknown byte**: Send `(15 - pos % 16)` padding bytes so the first unknown byte lands at position 15 of a block.
2. **Record the target block**: Encrypt with just the padding, note the target block's ciphertext.
3. **Brute-force**: For each candidate byte `b`, encrypt `padding + known_bytes + b`. Compare the target block's ciphertext. When it matches step 2, we've found the right byte.

```
Block layout for recovering byte at position pos=0 (pad_len = 15):

Our input:   A A A A A A A A A A A A A A A [S0] S1 S2 ...
Block:       └────── 15 A's + S0 ──────┘  └── next block ──

Brute force: A A A A A A A A A A A A A A A 'g'  (try '0'..'9','a'..'f')
Block:       └────── 15 A's + 'g' ──────┘
             If CT matches, S0 = 'g'
```

### Full recovery script

```python
import requests

SEED = "3159ba4686adaf03ad9bcd4313ad7360b56110be9156865c9623a36d113d8b04"
BASE = "https://hackforachangeruntime.vercel.app/api/food-voucher-manifest"

def encrypt(hex_data):
    r = requests.post(f"{BASE}?seed={SEED}&action=manifest",
                      json={"note_hex": hex_data}, timeout=30)
    return r.json()["cipher_hex"]

secret_len = 33
recovered = ""

for pos in range(secret_len):
    pad_len = 15 - (pos % 16)
    padding_hex = "41" * pad_len             # 'A' bytes

    target_block = pos // 16
    target_ct = encrypt(padding_hex)
    target_block_hex = target_ct[target_block * 32 : target_block * 32 + 32]

    # Try hex chars first (fast path)
    for c in "0123456789abcdef":
        guess_hex = padding_hex + recovered.encode().hex() + format(ord(c), '02x')
        guess_ct = encrypt(guess_hex)
        if guess_ct[target_block * 32 : target_block * 32 + 32] == target_block_hex:
            recovered += c
            break

    print(f"[{pos+1}/33] {recovered[-1]} → {recovered}")
```

Output:

```
[1/33]  9 → 9
[2/33]  8 → 98
[3/33]  d → 98d
...
[32/33] d → 98d4204376bde0f04e268a7fb4008e3d
[33/33] 0x01 → 98d4204376bde0f04e268a7fb4008e3d
```

The 33rd byte is `0x01` — PKCS#7 padding confirming the secret is exactly 32 bytes.

**audit_secret: `98d4204376bde0f04e268a7fb4008e3d`**

---

## Step 3 — Claim the Flag

Submit the recovered `audit_secret` as proof:

```
POST https://vgwukffsjudbybdeuodn.supabase.co/functions/v1/claim-runtime-flag
Authorization: Bearer <launch_token>
Content-Type: application/json

{ "token": "<launch_token>", "proof": "98d4204376bde0f04e268a7fb4008e3d", "slug": "food-voucher-manifest" }
```

The server returns the flag.

---

## Summary

| Component | Detail |
|---|---|
| **Vulnerability** | AES-ECB byte-at-a-time chosen-plaintext oracle |
| **Oracle** | `POST ?action=manifest {"note_hex": "<hex>"}` returns ECB encryption of `(input \|\| secret)` |
| **Block size** | 16 bytes (AES-128) |
| **Secret length** | 32 bytes (33 including PKCS#7 padding terminator) |
| **Attack** | Align unknown bytes at block boundaries, brute-force each position |
| **Recovered secret** | `98d4204376bde0f04e268a7fb4008e3d` |

The core flaw is using **ECB mode** with attacker-controlled plaintext prepended to a secret. Because ECB encrypts blocks independently, an attacker can align unknown bytes at the end of a block and brute-force them by comparing ciphertexts — a classic ECB byte-at-a-time oracle attack (as described in [Cryptopals Challenge 12](https://cryptopals.com/sets/2/challenges/12)).
