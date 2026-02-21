# CTF Writeup

**Challenge Name:** Mancity  
**Event:** Crypto CTF 2025  
**Category:** Cryptography (RSA – Structured Modulus Attack)  

> Decipher Mancity by exploiting RSA modulus secrets, bit by bit, relation by relation.

---

## 1) Overview

We are given:

- RSA modulus `n`
- Ciphertext `c`
- Public exponent `e = 1234567891`

From `mancity.py`, key generation is **non-standard** and structurally flawed.

Instead of two independent random primes, the primes are constructed with a deterministic relation.

---

## 2) Key Generation Logic

```python
def man(n):
    B = bin(n)[2:]
    M = ''
    for b in B:
        if b == '0':
            M += '01'
        else:
            M += '11'
    return int(M, 2)
```

For a 256-bit prime `p`, a related prime is generated:

- Let `x = p`
- Define:

```
r = man(p)
```

This mapping converts each bit:

| Original bit | Output bits |
|--------------|------------|
| 0            | 01         |
| 1            | 11         |

So:

```
man(p) = Σ (2*b_i + 1)·4^i
```

Then:

```python
B = bin(p)[2:] + '1' * 256
q = int(B, 2)
```

Which implies:

```
q = 2^256 · p + (2^256 − 1)
```

Let:

```
K = 2^256
```

Then:

```
q = Kp + (K − 1)
```

Finally:

```
n = p · q
  = p · (Kp + (K − 1))
```

But recall:

```
p = x
r = man(x)
```

So the modulus becomes:

```
n = (Kx + (K − 1)) · man(x)
```

This strong algebraic structure completely breaks RSA security.

---

## 3) Critical Modular Observation

Reduce `n` modulo `K`:

```
n = (Kx + (K − 1)) · man(x)
```

Since:

```
Kx ≡ 0 (mod K)
K − 1 ≡ −1 (mod K)
```

We get:

```
n ≡ −man(x) (mod K)
```

Therefore:

```
man(x) ≡ −n (mod K)
```

This leaks direct information about `x`.

---

## 4) Expressing man(x)

From construction:

```
man(x) = C + 2S
```

Where:

```
C = (4^256 − 1)/3
S = Σ b_i · 4^i
```

Thus:

```
C + 2S ≡ −n (mod K)
```

Rearranging:

```
2S ≡ (−n − C) (mod K)
```

Since `K = 2^256` is a power of two:

- Division by 2 is valid if RHS is even.
- This reveals **S modulo 2^255**.

But:

```
4^i = 2^(2i)
```

So bits of `S` directly reveal bits of `x`.

---

## 5) Recovering Lower 128 Bits

Observe:

```
4^128 = 2^256 = K ≡ 0 (mod K)
```

Therefore terms for `i ≥ 128` vanish mod `K`.

This means we recover:

```
b_0, b_1, ..., b_127
```

The lower 128 bits of `x`.

That cuts the search space from:

```
2^256 → 2^128
```

Already catastrophic.

---

## 6) Reconstructing Upper Bits

Write:

```
x = x_low + 2^128 · x_high
```

Where:

- `x_low` is known
- `x_high` has 128 unknown bits

Instead of brute forcing `2^128`, we exploit the full algebraic structure:

We directly recompute:

```
n_test = (Kx + (K−1)) · man(x)
```

and binary search for `x_high`.

Since the mapping from `x` to `n` is monotonic for valid range,
binary search converges efficiently.

---

## 7) Factorization

Once `x` is found:

```
p = Kx + (K − 1)
q = man(x)
```

Verify:

```
p · q == n
```

Then classical RSA decryption applies.

---

## 8) Decryption

```
φ(n) = (p − 1)(q − 1)
d = e^{-1} mod φ(n)
m = c^d mod n
```

Convert to bytes → flag recovered.

---

## 9) Exploitation Output

After deriving the lower 128 bits of `x` from the modular relation:

```
man(x) ≡ −n (mod 2^256)
```

we reconstructed:

```
x_low = 294059515476429790269751771133399813631
```

We then performed a binary search over the remaining 128 unknown upper bits (`x_high`), using the deterministic modulus construction:

```
n = (2^256 · x + (2^256 − 1)) · man(x)
```

### Search Progress

```
Starting binary search for x...
x_low: 294059515476429790269751771133399813631
Starting binary search for x_high...
Found x at iteration 127
```

### Recovered Secret Parameter

```
x = 97918363698716947075658593730252813578192444725864192759071101318494207364607
```

### Derived Primes

Using:

```
p = 2^256 · x + (2^256 − 1)
q = man(x)
```

We obtained:

```
p = 11338171907373815456673959643144436595447931742489890636387744547510799292993536478217233829945109394705560885589911191303642301888677829052802222509785087

q = 12980118888329561114281969993876754607095981711712555303794390136908262799373065828981224786253414810629276321980181325279687977358689569061320321526136831
```

### Verification

```
p · q == n  ✔
```

Factorization successful.

---

## 10) RSA Decryption

After computing:

```
φ(n) = (p − 1)(q − 1)
d = e^{-1} mod φ(n)
m = c^d mod n
```

We decrypted the ciphertext and recovered:

```
CCTF{M4nch3sReR_c0D!ng_wI7H_RSA}
```

---

### Final Result

The structured-prime construction completely broke RSA security.

By exploiting algebraic relations and modular leakage,  
the modulus was factored and the flag successfully recovered.


## 11) Core Vulnerability

This RSA instance is broken because:

- Primes are algebraically dependent
- Modulus leaks structured information modulo 2^256
- Bit-level mapping creates linear leakage
- Only 128 bits require reconstruction
- Deterministic prime relation destroys entropy

RSA security requires:

```
p and q independent & random
```

Here they are strongly correlated.

---

## 12) Cryptographic Lessons

1. Structured primes destroy RSA security.
2. Power-of-two modulus reductions leak bit structure.
3. Bitwise encodings can often be linearized algebraically.
4. Deterministic key relations are fatal.
5. "Custom prime generation" is almost always insecure.

---

## 13) Takeaway

This was not a brute-force problem.

It was an **algebraic structure exploitation** problem.

The attack succeeded because:

- We analyzed modulus construction.
- Reduced modulo 2^256.
- Extracted half the private information instantly.
- Solved remaining bits using structural relations.

RSA fails the moment prime independence is lost.

