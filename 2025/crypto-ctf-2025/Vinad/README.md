# CTF Writeup

**Challenge Name:** Vinad  
**Event:** Crypto CTF 2025  
**Category:** Cryptography (Broken RSA Construction)  

> Vinad's ‘random’ keys are as unpredictable as a cat. Poke its weak spots, steal the flag—chaos included!

---

## 1) Overview

We are given:

- Public list `R`
- Modulus `n`
- Ciphertext `c`
- Source code `vinad.py`

At first glance this resembles RSA, but both the **prime generation** and **public exponent** are constructed using a strange parity-based function.

The weakness lies in how `p` and `e` are generated.

---

## 2) Understanding the Custom Functions

### Parity Function

```python
def parinad(n):
    return bin(n)[2:].count("1") % 2
```

This returns:

```
Parity(n) = HammingWeight(n) mod 2
```

So it outputs either `0` or `1`.

---

### vinad Function

```python
def vinad(x, R):
    return int("".join(str(parinad(x ^ r)) for r in R), 2)
```

For each element `r` in `R`:

1. Compute `x ^ r`
2. Compute parity
3. Concatenate all parity bits

So:

```
vinad(x, R)
```

produces an integer built from parity outputs.

This is a **linear transformation over GF(2)**.

---

## 3) Key Generation Logic

Inside `genkey`:

```python
R = [getRandomNBitInteger(nbit) for _ in range(nbit)]
r = getRandomNBitInteger(nbit)

p = vinad(r, R)
q = getPrime(nbit)
```

So:

- `p` is **not randomly generated**
- `p` is deterministically computed from `r` and `R`

Since `R` is public, this leaks structure.

Then:

```python
e = vinad(r + 0x10001, R)
```

Critical detail:

Because parity is linear:

```
vinad(r + const, R)
```

behaves predictably relative to:

```
vinad(r, R)
```

Due to the linearity of XOR and parity over GF(2), this causes a catastrophic relationship.

---

## 4) Critical Structural Weakness

From generation:

```
p = vinad(r, R)
e = vinad(r + 0x10001, R)
```

Given linearity over GF(2):

```
vinad(r + k, R)
```

is strongly correlated with `vinad(r, R)`.

Empirically (and in this instance):

```
e = p
```

That completely breaks RSA.

Instead of a small public exponent (like 65537),
the exponent equals one of the primes.

---

## 5) Factoring the Modulus

We are given:

```
n
```

Running it through FactorDB reveals:

```
p = 4913890306465850...
q = 1182638817284945...
```

Thus:

```
n = p · q
```

So RSA is trivially factorable.

---

## 6) Encryption Scheme

Encryption:

```python
return pow(message + sum(R), e, n)
```

So ciphertext is:

```
c = (m + s)^e mod n
```

Where:

```
s = sum(R)
```

---

## 7) Decryption

Since `e = p`:

1. Compute:

```
φ(n) = (p − 1)(q − 1)
```

2. Compute modular inverse:

```
d = e^{-1} mod φ(n)
```

3. Decrypt:

```
m' = c^d mod n
```

4. Remove the offset:

```
m = m' − sum(R)
```

5. Convert to bytes → flag

---

## 8) Full Exploit Logic

```python
s = sum(R)

e = p

phi = (p - 1) * (q - 1)
d = inverse(e, phi)

m = pow(ct, d, n)
message = m - s

print(long_to_bytes(message))
```
---

### Final Flag

```
Flag : CCTF{s0lV1n9_4_Syst3m_0f_L1n3Ar_3qUaTi0n5_0vEr_7H3_F!3lD_F(2)!}

```

---

## 9) Root Cause

The entire scheme collapses because:

- `vinad()` is linear over GF(2)
- `p` is derived from public data
- `e` is deterministically related to `p`
- No true entropy protects the prime

RSA requires:

```
Independent, unpredictable primes
```

Instead:

```
p = linear_function(r)
```

and `R` is public.

This destroys unpredictability.

---

## 10) Cryptographic Lessons

1. Linear constructions over GF(2) leak structure.
2. Parity-based key derivations are weak.
3. Public parameters should never allow prime reconstruction.
4. Custom RSA modifications almost always fail.
5. Entropy is the backbone of RSA security.

---

## 11) Final Takeaway

This challenge looked chaotic and “random”.

In reality:

- It was a linear algebra problem.
- The modulus was weakly structured.
- Factoring was trivial.
- Decryption was classical RSA.

When prime generation loses randomness,
RSA collapses instantly.
