# VuwCTF 2026 — Crypto / concord

> **Challenge**
> - **Category:** Crypto
> - **Name:** concord
> - **Description:** *The university cut me off from their HPC clusters for "abusing university resources for personal gain", and I have to admit I was. I encrypted the flag on a powerful computer and my poor laptop can't decrypt it no matter how hard it tries. Please help me!*
> - **Flag format:** `VuwCTF{}`

## Files

| File                 | Description                                              |
| -------------------- | -------------------------------------------------------- |
| `concord.py`         | Server-side encryption script                            |
| `concord.ciphertext` | 48 bytes of AES-CBC ciphertext (hex)                    |
| `solve.py`           | Solver                                                  |

## Challenge source

```python
# concord.py
from random import seed, randbytes
from functools import reduce
import os

from Crypto.Cipher import AES

seed("concord")

def op(a, b):
    return (a + 1) * (b + 1) % 257 - 1

rand_input = randbytes(2 ** 30)
state = 0
key = []
for j in range(32):
    for i in range(1023):
        state = op(reduce(op, (op(rand_input[j + i], b) for b in rand_input)), state)
    key.append(state)

flag = os.environ.get("FLAG", "VuwCTF{xxxxxxxxxx}").encode(encoding="ascii")
cipher = AES.new(bytes(key), AES.MODE_CBC, iv=bytes.fromhex("243f57341528c28727458b8cc5f52786"))
print(cipher.encrypt(flag).hex())
```

And the ciphertext:

```
81df4fbb8ef58d5f6a7b4495706d76af5c5124160f15ec81015c24d3e6540c604326da488ddb77e76ab73a6231ccd7ab
```

## TL;DR

The key schedule is a giant computation over a **1 GiB** `randbytes` stream
with a hand-rolled "operation" `op(a, b) = (a+1)(b+1) % 257 - 1`. That
operation is secretly **multiplication in the field `F_257`**, disguised by
the shift `x ↦ x + 1`. Because of that structure:

1. The inner reduction over all `2^30` bytes collapses to a **single constant** `P - 1`,
   where `P = ∏(b + 1) mod 257` over every byte of `rand_input`.
2. The 32-byte AES key is then fully determined by that one number `P`.
3. `P` lives in `F_257*`, i.e. there are only **256 possible AES keys** — just
   brute-force all of them and decrypt until the flag appears.

```
VuwCTF{crypto_loves_mathematics}
```

---

## Background: `op` is multiplication in `F_257`

Let `g(x) = x + 1 mod 257`. Then, for byte-sized values `a, b ∈ {0..255}`,

```
g(op(a, b)) = op(a, b) + 1
            = (a + 1)(b + 1)      mod 257
            = g(a) · g(b)         mod 257
```

In other words, `op` is just the usual field multiplication conjugated by `g`.
Since `a + 1 ∈ {1..256}` is never `0` in `F_257`, every byte maps to a **non-zero**
element of `F_257`, i.e. an element of the multiplicative group `F_257*` of
order `256`.

This is the whole challenge: an enormous-looking computation over a group of
order 256, where every exponent is taken mod 256 for free.

---

## Step 1 — the inner reduction is constant

The inner expression is

```python
reduce(op, (op(rand_input[j + i], b) for b in rand_input))
```

Let `x = rand_input[j + i]` and let `N = 2**30` be the length of `rand_input`.
The generator contains `op(x, b)` for each byte `b`, and `reduce` folds them all
together with `op`. Applying `g` to the whole fold turns it into an ordinary
**product** in `F_257`:

```
g(inner) = ∏_{b in rand_input} g(op(x, b))
         = ∏_{b in rand_input} g(x) · g(b)
         = g(x)^N · P
```

where `P = ∏_{b in rand_input} (b + 1) mod 257`.

Now comes the magic. `g(x)` is a non-zero element of `F_257`, whose multiplicative
group has order `256`. And

```
N = 2^30  =  2^22 · 256  ≡  0   (mod 256)
```

so by Fermat's little theorem `g(x)^N = 1` — **for every byte `x`**. Therefore

```
g(inner) = P     ⇒     inner = P - 1     (a constant, independent of x!)
```

That one observation turns the whole inner loop into `state = op(P - 1, state)`.

## Step 2 — the state accumulates multiplicatively

The outer loop applies `state = op(P - 1, state)` exactly `1023` times per `j`,
and `state` carries over between `j` values. Starting from `state = 0`
(`g(0) = 1`), after `k` applications:

```
g(state) = g(P - 1)^k = P^k        (mod 257)
```

`key[j]` is captured after `1023 · (j + 1)` applications, so

```
g(key[j]) = P^(1023·(j + 1))     ⇒     key[j] = P^(1023·(j + 1)) - 1   (mod 257)
```

The full AES key is `bytes([key[0], ..., key[31]])`, which depends **only on P**.

## Step 3 — there are only 256 possible keys

`P = ∏(b + 1) mod 257` is a non-zero element of `F_257`, so `P ∈ {1, 2, ..., 256}`.
That means the whole key schedule has at most **256 outputs**. We don't even need
to regenerate the 1 GiB stream (and we don't need the HPC) — just try every `P`,
derive the key, and decrypt:

```python
from Crypto.Cipher import AES

IV = bytes.fromhex("243f57341528c28727458b8cc5f52786")
CT = bytes.fromhex("81df4fbb8ef58d5f6a7b4495706d76af"
                   "5c5124160f15ec81015c24d3e6540c60"
                   "4326da488ddb77e76ab73a6231ccd7ab")

for P in range(1, 257):
    key = bytes((pow(P, 1023 * (j + 1), 257) - 1) % 257 for j in range(32))
    pt  = AES.new(key, AES.MODE_CBC, iv=IV).decrypt(CT)
    if b"VuwCTF{" in pt:
        print(f"P = {P}, flag = {pt}")
```

That takes milliseconds on a laptop — exactly the opposite of what the flavour
text is complaining about.

---

## Full solution

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES

IV = bytes.fromhex("243f57341528c28727458b8cc5f52786")
CT = bytes.fromhex("81df4fbb8ef58d5f6a7b4495706d76af"
                   "5c5124160f15ec81015c24d3e6540c60"
                   "4326da488ddb77e76ab73a6231ccd7ab")

for P in range(1, 257):
    key = bytes((pow(P, 1023 * (j + 1), 257) - 1) % 257 for j in range(32))
    pt  = AES.new(key, AES.MODE_CBC, iv=IV).decrypt(CT)
    if b"VuwCTF{" in pt:
        print(f"[+] P = {P}")
        print(f"[+] flag = {pt.split(b'}')[0].decode() + '}'}")
        break
```

### Output

```
[+] P = 239
[+] key = 9ce9f30e29a83de073dd9e21c5f547fc8e5b33c4585e087f318b8678eb2be10f
[+] flag = VuwCTF{crypto_loves_mathematics}
```

---

## Flag

```
VuwCTF{crypto_loves_mathematics}
```

---

## Validation notes (how I confirmed the math)

Before trusting the collapse, I verified both parts numerically:

1. **Inner reduction is constant.** With a short `rand_input` of length divisible
   by 256, brute-force `reduce(op, (op(x, b) for b in ri))` returned the same
   value for many different `x`, equal to `P - 1`. (For a length not divisible
   by 256, e.g. 1000, it is *not* constant — `g(x)^N ≠ 1` — which is a great
   sanity check that the argument is what actually matters.)

2. **State formula matches brute force.** Replicating the *exact* challenge loop
   (32 × 1023 iterations, `state` carried over) with a 2048-byte `rand_input`
   produced a key byte-for-byte identical to the closed form above.

3. **The byte stream is reproducible / irrelevant.** Regenerating
   `randbytes(2**30)` (in chunks, to dodge CPython's 2³¹-bit `getrandbits`
   limit) gives the same stream on 3.11 and 3.14. Since the key only has 256
   candidates anyway, the stream is only needed to *confirm* which `P` — and the
   256-way brute force finds the flag without it.

---

## Mitigation / takeaway

- A custom "one-way" operation that secretly forms a **finite group of small
  order** is not one-way: every intermediate collapses to an exponent mod the
  group order. Here the group `F_257*` has order 256, so the "huge" key
  schedule has at most 256 distinct outputs.
- Whenever a cipher key is derived from a value in a tiny space, it is
  immediately brute-forceable. The key schedule should hash a high-entropy seed
  with a standard KDF instead of hand-rolling `op` compositions.
- The flavor text ("my laptop can't decrypt it") is the hint: the computation
  *looks* O(2^30 · 32736), but the mathematical structure makes it O(256).
