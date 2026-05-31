# Poverty Action Cipher — SDG 1 Challenge Writeup

> **Challenge:** Three-layer classical crypto puzzle recovering a 32-hex proof from an SDG 2030 Agenda pledge excerpt.
>
> **Proof:** `c5de6c1afb5a5e8d3e82a1a74aa2b176`

## Approach

### Layer 1 — ROT13 substitution

The API returns a ciphertext that looks like monoalphabetic substitution. Trying ROT13 reveals the stage-1 plaintext:

```
RAQVAT CBIREGL VA NYY VGF SBEZF ... FGNTR2: TDZNDZJ ...
```

ROT13 decode:

```
ENDING POVERTY IN ALL ITS FORMS EVERYWHERE REMAINS THE GREATEST
GLOBAL CHALLENGE FACING THE WORLD TODAY AND AN INDISPENSABLE
REQUIREMENT FOR SUSTAINABLE DEVELOPMENT.
STAGE2: GQMAQMW RN GYT ASPIT OMBLJA OF NHSQLGGQHLDT.
CR XECGOK GPTR QW UAM PGOT HR TXDW JKUQGB.
VBGTM3ACA: 1i295l35oktde4nj1n5j5u29y1emh0r41i5u4c3hi...
```

The `FGNTR2` tag becomes `STAGE2` under ROT13 (simple shift of each letter).

### Layer 2 — Vigenère with key `DIGNITY`

The hint says *"Stage 2 uses an SDG 1 themed seven-letter crib word in the title bar — it is also the key."*

The word **DIGNITY** (prominently featured in "*DIGNITY OF ALL HUMAN BEINGS IS FOUNDATIONAL*") is the Vigenère key.

Applying Vigenère decryption with key `DIGNITY` to the full stage-2 ciphertext:

```
GQMAQMW RN GYT ASPIT OMBLJA OF NHSQLGGQHLDT.
CR XECGOK GPTR QW UAM PGOT HR TXDW JKUQGB.
VBGTM3ACA: 1i295l35oktde4nj1n5j5u29y1emh0r41i5u4c3hi3...
```

Produces:

```
DIGNITY OF ALL HUMAN BEINGS IS FOUNDATIONAL.
WE PLEDGE THAT NO ONE WILL BE LEFT BEHIND.
STAGE3HEX: 1a295f35bcafb4fd1a5b5b29a1beb0e41a5b4e3ea3a9a7fd06...
```

The `VBGTM3ACA` header (which was also Vigenère'd) decodes to **`STAGE3HEX`**.

The hex string after the colon becomes valid hex (letters a-f only) after Vigenère decryption.

### Layer 3 — XOR with 8-byte hash-derived key

The hint says: *"Stage 3 verb appears in the cleartext you produced. Hash it, take the first eight bytes, XOR."*

The stage-3 hex decodes to 115 bytes. The verb is **`eradicate`** —the first word of the stage-3 plaintext itself (a self-referential hint: *"Stage 3 verb appears in the cleartext you produced"*). SHA-256 of `"eradicate"` produces the 8-byte XOR key `5f7b1e71f5ecf5a9`.

XOR-decrypting the hex data yields:

```
ERADICATE EXTREME POVERTY FOR ALL PEOPLE EVERYWHERE
BY TWO THOUSAND THIRTY. PROOF: c5de6c1afb5a5e8d3e82a1a74aa2b176
```

The 32 hex characters after `PROOF:` are the proof value.

### The proof

**`c5de6c1afb5a5e8d3e82a1a74aa2b176`**

Submit via the claim-runtime-flag endpoint with slug `poverty-action-cipher` to receive the flag.

### Decryption summary

| Stage | Algorithm | Key / Parameter |
|-------|-----------|-----------------|
| 1 | ROT13 | — |
| 2 | Vigenère | `DIGNITY` |
| 3 | Repeating-byte XOR | 8-byte key from hashing a verb from the cleartext |
