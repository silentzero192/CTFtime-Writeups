# CTF Writeup

**Challenge Name:** Custom RSA  
**Platform:** Blitz CTF 2025
**Category:** Crypto  
**Difficulty:** Medium  
**Time Spent:** ~50 minutes  

---

## 1) Goal (What was the task?)

We were given a custom RSA implementation (`chall.py`) along with its public parameters and ciphertext in `output.txt`.

The goal was to analyze the flawed RSA construction and recover the original plaintext flag in the format:

```
Blitz{...}
```

---

## 2) Key Clues (What mattered?)

From `chall.py`:

```python
p = getPrime(256)
q = getPrime(256)
x = getPrime(128)
y = getPrime(128)
z = getPrime(128)

e = x * y * z
n = p * q * y
hint1 = p % x
hint2 = p % z
```

Important observations:

- `n = p * q * y` → not standard RSA modulus (extra factor `y`)
- `e = x * y * z` → exponent is composite
- `y` appears in both `n` and `e`
- Two hints:
  - `p % x`
  - `p % z`

This structure leaks enough information to recover `p`.

---

## 3) Plan (Your first logical approach)

- Compute `gcd(n, e)` to recover shared factor `y`.
- Since `e = x * y * z`, divide by `y` to get `x * z`.
- Factor `x * z` to obtain `x` and `z`.
- Use hints (`p % x`, `p % z`) and apply **Chinese Remainder Theorem (CRT)** to reconstruct `p mod (x*z)`.
- Recover full `p` by searching for a valid prime candidate.
- Factor `n`, compute `phi`, derive private key `d`.
- Decrypt ciphertext.

---

## 4) Steps (Clean execution)

### Step 1: Recover `y`

Since `y` is common in both `n` and `e`:

```python
from Crypto.Util.number import GCD
y = GCD(n, e)
```

This gives:

```
y = 215200262830198930084990116270235828097
```

---

### Step 2: Recover `x` and `z`

Since:

```
e = x * y * z
```

We compute:

```
xz = e // y
```

Then factor `xz`:

```python
from primefac import primefac
x, z = list(primefac(xz))
```

---

### Step 3: Use CRT to Recover `p mod (x*z)`

We are given:

```
p % x = hint1
p % z = hint2
```

Using Chinese Remainder Theorem:

```python
from sympy.ntheory.modular import crt

moduli = [x, z]
remainders = [hint1, hint2]
p_mod_xz, _ = crt(moduli, remainders)
```

Now:

```
p ≡ p_mod_xz (mod x*z)
```

---

### Step 4: Recover Prime `p`

We brute-force small multiples:

```python
M = x * z

for k in range(1000):
    candidate = p_mod_xz + k * M
    if isPrime(candidate) and n % (candidate * y) == 0:
        p = candidate
        break
```

Once valid prime `p` is found:

```
q = n // (p * y)
```

---

### Step 5: Compute Private Key and Decrypt

Compute totient:

```python
phi = (p - 1) * (q - 1) * (y - 1)
```

Compute modular inverse:

```python
d = inverse(e, phi)
```

Decrypt:

```python
pt = pow(c, d, n)
long_to_bytes(pt)
```

---

## Full Solution Script

```python
from Crypto.Util.number import *
from sympy.ntheory.modular import crt
from primefac import primefac

hint1 = 154888122383146971967744398191123189212
hint2 = 130654136341446094800376989317102537325

n = 1291778230841963634710522186531131140292748304311790700929719174642140386189828346122801056721461179519840234314280632436994655344881023892312594913853574461748121277453328656446109784054563731
e = 9397905637403387422411461938505089525132522490010480161341814566119369497062528168320590767152928258571447916140517
c = 482782367816881259357312883356702175242817718119063880833819462767226937212873552015335218158868462980872863563953024168114906381978834311555560455076311389674805493391941801398577027462103318

# Recover y
y = GCD(n, e)

# Recover x and z
xz = e // y
x, z = list(primefac(xz))

# Reconstruct p mod (x*z)
moduli = [x, z]
remainders = [hint1, hint2]
p_mod_xz, _ = crt(moduli, remainders)

# Find correct p
M = x * z
p = None
for k in range(1000):
    candidate = p_mod_xz + k * M
    if isPrime(candidate) and n % (candidate * y) == 0:
        p = candidate
        break

q = n // (p * y)

phi = (p - 1) * (q - 1) * (y - 1)
d = inverse(e, phi)

pt = pow(c, d, n)
print(long_to_bytes(pt).decode())
```

---

## 5) Solution Summary (What worked and why?)

This RSA implementation was flawed because:

- The modulus included an extra prime factor (`y`).
- The public exponent shared a factor with `n`.
- Hints leaked modular residues of `p`.

By exploiting:

- `gcd(n, e)` → recover shared prime
- Factoring partial exponent
- CRT to reconstruct prime
- Standard RSA decryption

We fully broke the scheme.

This demonstrates why RSA parameters must be carefully constructed.

---

## 6) Flag

```
Blitz{H0w_D4r3_y0u_br34k_My_RSA_Ag41n!!!}
```

---

## 7) Lessons Learned

- Never let `e` share factors with `n`.
- Avoid adding extra primes into modulus.
- Partial modular hints can completely break RSA.
- CRT is extremely powerful in cryptanalysis.
- Always check `gcd(n, e)` in custom RSA challenges.

---

## 8) Personal Cheat Sheet

- `GCD(n, e)` → Check shared factors  
- If `e` is composite → Factor it  
- Use CRT for modular reconstruction  
- Recover `p` → Factor `n` → Compute `phi`  
- RSA breaks easily when mathematical assumptions fail  
