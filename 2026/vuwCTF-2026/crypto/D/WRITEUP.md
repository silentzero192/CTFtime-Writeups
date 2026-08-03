# VuwCTF 2026 — Crypto — `D`

> **Flag:** `VuwCTF{permuting_permutation_polynomials}`

| | |
|---|---|
| **Category** | Crypto |
| **Description** | *Not the programming language, sadly* |
| **Challenge files** | `D.sage` (1,138 bytes, MD5 `15b556d8411de7a66ce2d41ad04b2ebe`)<br>`flag.png.encrypted` (11,600 bytes, MD5 `07aea996646f31cf88ca11903a344ce6`) |
| **Recovered file** | `flag.png` (11,587 bytes, MD5 `a7dc71ef329f118f7209437d6b9eb006`, 1110×58 RGBA) |
| **Difficulty** | Medium–Hard |
| **Tags** | Dickson polynomials, permutation polynomials, `GF(2^128)`, SPN, CBC, fixed PRNG seed |
| **Solver** | [`solve.py`](solve.py) (pure stdlib, ~30 s) · [`sol.c`](sol.c) (`pclmulqdq`, ~70 ms) |

---

## TL;DR

`D.sage` is a 16-round SPN over `GF(2^128)` run in CBC mode. Its only non-linear
component is the polynomial built by `D(13, a)`, and the challenge description tells
you what to google: **D is not the programming language, it's a Dickson polynomial**.
In characteristic 2 the recurrence in the source collapses exactly onto the
first-kind Dickson polynomial

```
D_n(y, a) = u^n + v^n        where  u + v = y,  u·v = a
```

`D_13(·, a)` permutes `GF(2^128)` because `gcd(13, 2^256 − 1) = 1`, so it is a
**permutation polynomial** — an invertible S-box. The composition law
`D_m(D_n(x,a), a^n) = D_{mn}(x,a)` gives its inverse as `D_m(·, a^13)` with
`m = 13⁻¹ mod (2^256 − 1)`. `m` is a 255-bit number, so `D_m` is never built as a
polynomial; it is evaluated in the quotient ring `F[T]/(T² + cT + a^13)`.

Everything else is free: the key comes from `random.Random(b"p-box")` — a **fixed
seed** — and the byte shuffle is a ShiftRows-style bijection. Peel off 16 rounds per
block, undo the CBC chain, strip the padding, and out falls a PNG of the flag.

![flag](flag.png)

---

## 1. Recon

Two files, and one of them is the source, so this is a "read carefully, then do the
math" challenge rather than a guessing game.

```console
$ ls -l
-rw------- 1 null null  1138 Aug  1  2026 D.sage
-rw------- 1 null null 11600 Aug  1  2026 flag.png.encrypted

$ file flag.png.encrypted
flag.png.encrypted: data

$ python3 -c "
import math,collections
d=open('flag.png.encrypted','rb').read()
c=collections.Counter(d)
print('len', len(d), 'len%16 =', len(d)%16)
print('entropy %.4f bits/byte' % -sum(v/len(d)*math.log2(v/len(d)) for v in c.values()))"
len 11600 len%16 = 0
entropy 7.9854 bits/byte
```

11,600 = 16 × 725, full entropy, no structure to carve. Everything is in the source:

```python
import random, itertools, operator
key = random.Random(b"p-box").randbytes(128)

with open("flag.png", "rb") as f:
    flag = f.read()

p = len(flag)%16
if p!= 0:
    p = 16 - p
    flag+=bytes([p]*p)

F.<x> = GF(340282366920938463463374607431768211456)
R.<y> = PolynomialRing(F)

def D(n,a):
    if n == 0:
        return 0
    if n == 1:
        return y
    return y*D(n-1,a) - a*D(n-2, a)

p = D(13, F.from_integer(19))

@operator.call
def ks():
    while True:
        for i in range(8):
            l = F.from_bytes(key[i:i+16])
            for j in range(16):
                yield l.to_integer()
                l = p(l)

def encrypt_block(b):
    b = int.from_bytes(b)
    for i in range(16):
        b = p(F.from_integer(next(ks)^^b)).to_bytes()
        c = [0]*16
        for i in range(4):
            for j in range(4):
                c[j * 4 + i] = b[i + 4 * ((j + i) % 4)]
        b = int.from_bytes(bytes(c))

    return b.to_bytes(16)

s=bytes(16)
with open("flag.png.encrypted", "wb+") as f:
    for i in range(len(flag) // 16):
        s=encrypt_block(a^^b for a,b in zip(flag[i*16:i*16+16],s))
        f.write(s)
```

Four observations before touching any math:

1. `340282366920938463463374607431768211456` = **2¹²⁸**, so `F = GF(2^128)` and a field
   element is exactly one 16-byte block.
2. `random.Random(b"p-box")` is a **hard-coded seed**. The 128-byte key is not secret
   — it is reproducible with one line of Python. There is no key-recovery problem here.
3. The bottom loop is textbook **CBC** with an all-zero IV: `C_i = E(P_i ⊕ C_{i−1})`.
4. `encrypt_block` is a 16-round **substitution-permutation network**: XOR in a round
   constant, apply `p` (substitution), shuffle bytes (permutation). Both the XOR and
   the shuffle are trivially invertible, so *the entire challenge is inverting `p`*.

So the whole thing reduces to one question: **what is `p`, and can it be inverted?**

---

## 2. "Not the programming language, sadly"

The file is `D.sage` and the function is `D(n, a)`. [D](https://dlang.org/) *is* a
programming language, and the description tells you it isn't that one. The other
famous `D(n, a)` is the **Dickson polynomial**, and the recurrence matches on sight:

```python
def D(n,a):
    if n == 0: return 0
    if n == 1: return y
    return y*D(n-1,a) - a*D(n-2, a)
```

The textbook first-kind Dickson polynomial has `D_0 = 2`, not `0`, so at first glance
this looks like the *second* kind. It isn't — and the reason is the whole trick.

Solve the recurrence. The characteristic equation is `t² − y·t + a = 0`, with roots
`u, v` satisfying

```
u + v = y        u·v = a
```

The general solution is `D_n = A·uⁿ + B·vⁿ`. Plugging in `D_0 = 0` gives `B = −A`,
and `D_1 = y` gives `A·(u − v) = y = u + v`, so

```
A = (u + v) / (u − v)
```

**In characteristic 2, `u − v = u + v`**, so `A = 1` and the whole thing collapses to

```
D_n(y, a) = uⁿ + vⁿ
```

which is precisely the **first-kind Dickson polynomial** — consistent with `D_0 = 2 = 0`
in char 2. The `0` in the source is not a different polynomial family, it is the
first-kind polynomial *written correctly for char 2*.

That identity — `D_n` is "the sum of the n-th powers of the two roots" — is the only
fact needed for the rest of the challenge.

---

## 3. Why the S-box is invertible

A classical result of Nöbauer: **`D_n(·, a)` with `a ≠ 0` permutes `GF(q)` if and only
if `gcd(n, q² − 1) = 1`.**

Here `n = 13` and `q = 2¹²⁸`, so we need `gcd(13, 2²⁵⁶ − 1)`. The multiplicative order
of 2 mod 13 is 12, and `12 ∤ 256`, so 13 does not divide `2²⁵⁶ − 1`:

```console
$ python3 -c "
from math import gcd
print('ord_13(2) =', next(k for k in range(1,13) if pow(2,k,13)==1))
print('gcd(13, 2^256-1) =', gcd(13, 2**256-1))"
ord_13(2) = 12
gcd(13, 2^256-1) = 1
```

So `p` is a genuine permutation polynomial of `GF(2^128)` and the cipher is
well-defined. (This is also why 13 was chosen and not, say, 3 or 5 — `gcd(3, 2²⁵⁶−1) = 3`
and `gcd(5, 2²⁵⁶−1) = 5`, both of which would have made `p` non-injective.)

Note that "it is a permutation" is not the same as "you can invert it". Degree-13
root-finding over `GF(2^128)` *is* possible (Cantor–Zassenhaus, or
`gcd(z^q − z, p(z) − c)`), but doing it 11,600 times is unpleasant. There is a much
better way.

---

## 4. Inverting the S-box

### 4.1 The composition law

Dickson polynomials compose almost like power maps:

```
D_m( D_n(x, a), aⁿ ) = D_{m·n}(x, a)
```

which is immediate from the root form: if `u + v = x` and `uv = a`, then the two roots
belonging to `D_n(x,a)` are `uⁿ, vⁿ` (their product is `aⁿ`, hence the parameter
change), so applying `D_m` gives `u^{mn} + v^{mn}`.

Now pick `m` with `m·13 ≡ 1 (mod q² − 1)`. Since `u, v ∈ GF(q²)*`, we get
`u^{13m} = u` and `v^{13m} = v`, so

```
D_m( D_13(x, a), a^13 ) = D_{13m}(x, a) = u + v = x
```

**The inverse of `p = D_13(·, a)` is `D_m(·, a¹³)`.**

```console
$ python3 -c "print(hex(pow(13, -1, 2**256 - 1)))"
0x7627627627627627627627627627627627627627627627627627627627627627
```

(That pretty repeating pattern is not a coincidence: `13 | 2¹² − 1 = 4095`, so the
inverse of 13 in `Z/(2^k − 1)` repeats with a 12-bit period. It becomes useful in §7.)

### 4.2 Evaluating `D_m` without building `D_m`

`m ≈ 2²⁵⁵`, so `D_m` as an actual polynomial has degree ≈ 2²⁵⁵. It must be evaluated
via its root form instead. Given a ciphertext value `c` to invert, set `b = a¹³` and
work in the quotient ring

```
R = F[T] / (T² + c·T + b)
```

By construction the two roots are `u = T` and `v = c + T` (they sum to `c` and multiply
to `b`, since `T·(T + c) = b` in `R`). `R` is a field when the quadratic is irreducible
and `F × F` when it splits, but **either way** the map `σ : T ↦ c + T` is a ring
automorphism swapping the two roots. So if

```
T^m = A + B·T
```

then `v^m = σ(u^m) = A + B·(c + T)`, and in characteristic 2 everything cancels:

```
D_m(c, b) = u^m + v^m = (A + B·T) + (A + B·c + B·T) = B·c
```

**The inverse S-box is: exponentiate `T` to the power `m` in `F[T]/(T² + cT + b)`,
take the coefficient of `T`, multiply by `c`.** One 255-bit exponentiation in a
quadratic extension per inversion — no root-finding, no `GF(2^256)` construction, no
embedding maps.

Edge case: `c = 0` maps to `0`, which is consistent (`D_13(0, a) = 0`, visible straight
from the recurrence).

```python
def dickson13_inv(c):
    if c == 0:
        return 0
    ...
    return gmul(acc[1], c)      # B · c
```

---

## 5. Everything else

### 5.1 The key is not secret

```python
key = random.Random(b"p-box").randbytes(128)
```

A fixed seed. One line reproduces it:

```console
$ python3 -c "
import random
print(random.Random(b'p-box').randbytes(128).hex()[:64], '...')"
badd68f58d3bcd1fc3353b7b6a4dfc51039e49d898269f956dcae1901132cd7c ...
```

### 5.2 The keystream repeats every 128 values

```python
@operator.call
def ks():
    while True:
        for i in range(8):
            l = F.from_bytes(key[i:i+16])
            for j in range(16):
                yield l.to_integer()
                l = p(l)
```

Note the sliding window: `key[0:16]`, `key[1:17]`, …, `key[7:23]` — only the first 23
bytes of the 128-byte key are ever used. Each seed is iterated through `p` 16 times,
giving `8 × 16 = 128` values, and then `while True` **restarts the identical loop**.
So the round constants are a fixed 128-entry table with period 128, i.e. period 8
blocks. Block `i` round `r` uses `ks[(16i + r) mod 128]`.

### 5.3 The P-box

```python
c[j * 4 + i] = b[i + 4 * ((j + i) % 4)]
```

Read as a 4×4 column-major state this is AES's ShiftRows. As a flat table:

```
dst  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
src  0  5 10 15  4  9 14  3  8 13  2  7 12  1  6 11
```

A bijection, so inverting it is `raw[PBOX[d]] = cur[d]`.

### 5.4 Putting it together

Encryption of one block is

```
for r in 0..15:   b ← PBOX( D_13( ks[r] ⊕ b ) )
```

so decryption is the same loop backwards:

```
for r in 15..0:   b ← D_13⁻¹( PBOX⁻¹(b) ) ⊕ ks[r]
```

and then the CBC unchaining `P_i = D(C_i) ⊕ C_{i−1}` with `C_{−1} = 0`.

### 5.5 The padding is *not* PKCS#7

```python
p = len(flag)%16
if p!= 0:
    p = 16 - p
    flag+=bytes([p]*p)
```

When the length is already a multiple of 16, **no padding block is added** — so a
plaintext ending in `\x01` would be ambiguous. It does not matter here (the real pad
is 13 bytes and the result ends in a valid `IEND` chunk), but a solver should check
rather than blindly strip.

---

## 6. Which `GF(2^128)`? — the one real trap

`GF(2^128)` is not *a* field, it is a field *representation*. `F.from_integer` /
`to_integer` fix the basis as "bit *i* = coefficient of *x^i*", but which irreducible
polynomial does Sage pick when you write `GF(2^128)` with no `modulus=` argument?

Sage's rule (`sage/rings/polynomial/polynomial_ring.py`):

> If `algorithm` is `None`, use `x − 1` in degree 1. In degree > 1, the **Conway
> polynomial** is used if it is found in the database. Otherwise, the algorithm
> `minimal_weight` is used if `p = 2` […]

So: is there a Conway polynomial for `2^128`? **No** — the database jumps from 127
straight to 131:

```console
$ pip install conway-polynomials
$ python3 -c "
import conway_polynomials as cp
d = cp.database()[2]
print('128 in db:', 128 in d)
print([n for n in sorted(d) if 120 <= n <= 140])"
128 in db: False
[120, 121, 125, 126, 127, 131, 132, 133, 137]
```

So Sage falls back to `minimal_weight`, which is NTL's `BuildSparseIrred`: the
irreducible polynomial of lowest weight, ties broken by smallest exponents. There is
**no irreducible trinomial** of degree 128, and the first irreducible pentanomial is
`x¹²⁸ + x⁷ + x² + x + 1`:

```console
$ python3 -c "... exhaustive search over GF(2)[x] ..."
irreducible trinomials x^128 + x^k + 1: []
first irreducible pentanomials (k3,k2,k1): [(7, 2, 1)]
```

That is the familiar AES-GCM reduction constant `0x87`, which is a nice bonus: the
`pclmulqdq`-based `sol.c` gets to use the standard fast reduction.

If you guess this wrong, everything still *runs*, it just produces garbage — and
conveniently, **the plaintext is a PNG**, so the 8-byte magic `89 50 4E 47 0D 0A 1A 0A`
is a free oracle telling you whether your field is right on the very first block.

### 6.1 A `to_bytes()` footgun

`F.to_bytes()` returns a fixed-width big-endian encoding whose length comes from the
field order. The current implementation is

```python
length = ((order - 1).nbits() + 7) // 8      #  = 16  for GF(2^128)
```

but before Sage issue **#41545** it was

```python
length = (order.nbits() + 7) // 8            #  = 17  for GF(2^128)  (!)
```

because `(2¹²⁸).nbits() == 129`. On an older Sage, `p(...).to_bytes()` would hand the
P-box a **17**-byte string, whose first byte is always `0x00`; `b[i + 4*((j+i)%4)]`
only reads indices 0–15, so the low byte of every S-box output would be silently
discarded and a zero byte injected in its place. The round function would stop being
a bijection and the challenge would be unsolvable. Worth knowing if you try to
reproduce `D.sage` locally and get a file you cannot decrypt: this challenge needs a
Sage new enough to have that fix.

---

## 7. Making it fast without Sage

`725 blocks × 16 rounds = 11,600` S-box inversions, each a 255-bit exponentiation in a
quadratic extension of `GF(2^128)`. Done naively that is ~20 M field multiplications,
which is not something pure Python enjoys. Three tricks bring [`solve.py`](solve.py) down to
~30 seconds with **zero dependencies**:

**1. Carry-less multiply via one big-int multiply.** Spread each operand so bit *i*
lands in byte slot *i*, then multiply normally. Each output slot accumulates at most
128 partial products — which fits in a byte — so no carry ever crosses a slot
boundary, and masking with `0x0101…01` recovers the carry-less product.

```python
sa = int.from_bytes(b"".join([_EXPAND[c] for c in a.to_bytes(16, "little")]), "little")
sb = int.from_bytes(b"".join([_EXPAND[c] for c in b.to_bytes(16, "little")]), "little")
prod = (sa * sb) & _SLOT_MASK
```

≈ 5 µs per multiply, versus ≈ 12.5 µs for the obvious shift-and-XOR loop.

**2. Squaring and multiply-by-constant are linear maps.** In characteristic 2,
`x ↦ x²` is `GF(2)`-linear, and so is `x ↦ b·x` for fixed `b`. Both become 16 table
lookups (0.7 µs) instead of a general multiply. `b = a¹³` is a global constant, so
ring squaring `(r₀ + r₁T)² = (r₀² + b·r₁²) + (c·r₁²)T` costs three lookups and only one
real multiply.

**3. Walk the exponent in base 2¹².** Because `13 | 2¹² − 1`, the exponent is

```
m = 0x7 627 627 627 … 627        (the 12-bit block "627" repeats 21 times)
```

Horner over 12-bit digits needs **21** ring multiplications in the main loop (28
including the two small precomputations) instead of the **129** that plain
square-and-multiply needs, since `popcount(m) = 129`. The squarings are unchanged, so
the wall-clock saving is a bit under 2×:

```python
M_DIGITS = [0x7] + [0x627] * 21
step = rpow_small(T, M_DIGITS[1])          # computed once per inversion
acc  = rpow_small(T, M_DIGITS[0])
for _ in M_DIGITS[1:]:
    for _ in range(12):                    # acc = acc^(2^12)
        acc = rsqr(acc)
    acc = rmul(acc, step)
```

[`sol.c`](sol.c) is the same algorithm with `_mm_clmulepi64_si128`, and finishes the
whole file in ~70 ms if you want the instant version.

---

## 8. Running it

```console
$ python3 solve.py flag.png.encrypted flag.png
[+] D_13 inverse verified
[+] keystream derived from random.Random(b'p-box')
[*] block  725/725  (100%, 29.0s)
[+] re-encryption matches the ciphertext exactly
[+] stripped 13 padding bytes
[+] wrote flag.png (11587 bytes) - open it to read the flag

$ file flag.png
flag.png: PNG image data, 1110 x 58, 8-bit/color RGBA, non-interlaced
```

The solver does not just trust its output: it re-encrypts the recovered plaintext with
the forward cipher and asserts the result is byte-identical to `flag.png.encrypted`,
which rules out any lucky-looking-but-wrong field or bit-order choice.

Or, with a C compiler:

```console
$ gcc -O2 -mpclmul -msse4.1 -o sol sol.c
$ python3 -c "import random; open('key.bin','wb').write(random.Random(b'p-box').randbytes(128))"
$ ./sol key.bin flag.png.encrypted flag_raw.png     # 0.07 s (padding left on)
```

---

## 9. Flag

![flag](flag.png)

```
VuwCTF{permuting_permutation_polynomials}
```

Which is exactly what the challenge was: a **permutation polynomial** used as an
S-box, wrapped in a byte **permutation** — permuting permutation polynomials.

---

## Appendix — checklist of things that could have burned you

| Trap | Why it bites | Fix |
|---|---|---|
| Reading `D` as a second-kind Dickson polynomial | `D_0 = 0` looks like the second kind | In char 2 the leading coefficient `(u+v)/(u−v)` is 1, so it is first-kind |
| Assuming `GF(2^128)` means AES-GCM's bit order | GCM uses reflected bit order | Sage's `from_integer` is plain "bit *i* = *x^i*"; only the *modulus* coincides |
| Guessing the Conway polynomial | There is none for `2^128` | `minimal_weight` → `x¹²⁸ + x⁷ + x² + x + 1` |
| Building `D_m` as a polynomial | Degree ≈ 2²⁵⁵ | Evaluate in `F[T]/(T² + cT + b)` |
| Using `m = 13⁻¹ mod (q − 1)` | The roots live in `GF(q²)`, not `GF(q)` | `m = 13⁻¹ mod (q² − 1)` |
| Treating the padding as PKCS#7 | No pad block when `len % 16 == 0` | Verify before stripping |
| Forgetting the keystream wraps | Period is 128 values = 8 blocks | Index with `(16·i + r) mod 128` |
| Feeding rounds the key in forward order | It is an SPN, not a stream XOR | Consume round constants in reverse when decrypting |
