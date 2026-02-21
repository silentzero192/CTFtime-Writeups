# CTF Writeup

**Challenge Name:** Custom RSA Revenge  
**Platform:** Blitz CTF 2025  
**Category:** Crypto  
**Difficulty:** Medium-Hard  
**Time Spent:** ~40 minutes  

---

## 1) Goal (What was the task?)

We were given a custom RSA implementation (`chall.py`) and its generated parameters inside `output.txt`.

The objective was simple:

Recover the encrypted flag:

```
Blitz{...}
```

---

## 2) Key Clues (What mattered?)

From `chall.py`:

```python
from Crypto.Util.number import long_to_bytes, getPrime, bytes_to_long

m = b"Blitz{REDACTED}"

p = getPrime(150)
q = getPrime(150)
e = getPrime(128)

n = p * q
mod_phi = (p - 1) * (q - 1) * (e - 1)
d = pow(e, -1, mod_phi)

print(mod_phi)
print(n)
c = pow(bytes_to_long(m), e, n)
print(c)
```

### 🔎 Critical Observations

This is **NOT standard RSA**.

Normally:

```
phi(n) = (p - 1)(q - 1)
```

But here:

```
mod_phi = (p - 1)(q - 1)(e - 1)
```

And they compute:

```
d = e⁻¹ mod mod_phi
```

That means the private exponent is computed modulo:

```
(p - 1)(q - 1)(e - 1)
```

instead of:

```
(p - 1)(q - 1)
```

And worst of all…

👉 **They print `mod_phi` publicly.**

So we now know:

```
(p - 1)(q - 1)(e - 1)
```

That completely destroys security.

---

## 3) Plan (First Logical Approach)

We know:

- `p` is 150 bits
- `q` is 150 bits
- `e` is 128 bits
- `mod_phi = (p - 1)(q - 1)(e - 1)`
- `n = p * q`

Strategy:

1. Factor `mod_phi`
2. Look for primes where:
   ```
   prime - 1 | mod_phi
   ```
3. Filter candidates based on bit lengths
4. Find triple `(p, q, e)` satisfying:
   ```
   (p - 1)(q - 1)(e - 1) = mod_phi
   ```
5. Verify:
   ```
   p * q == n
   ```
6. Compute `d`
7. Decrypt ciphertext

---

## 4) Exploitation Steps

### Step 1: Factor Candidates from `mod_phi`

If:

```
prime - 1 divides mod_phi
```

then:

```
prime = divisor + 1
```

So we:

- Enumerate divisors of `mod_phi`
- Check if `divisor + 1` is prime
- Collect candidates

```python
from sympy import divisors
from Crypto.Util.number import isPrime

def get_primes(modulus: int):
    primes = []
    for i in divisors(modulus):
        if isPrime(i + 1):
            primes.append(i + 1)
    return primes
```

---

### Step 2: Filter Valid Prime Sizes

We only keep primes of sizes:

```
{127, 128, 149, 150}
```

```python
def keep_valid_primes(primes):
    valid_lengths = {127, 128, 149, 150}
    return [p for p in primes if p.bit_length() in valid_lengths]
```

After filtering, we get small set of valid candidates.

---

### Step 3: Find the Correct Triple (p, q, e)

We search combinations:

```python
from itertools import combinations

def find_pqe(primes, mod_phi):
    for p, q, r in combinations(primes, 3):
        if (p - 1) * (q - 1) * (r - 1) == mod_phi:
            return p, q, r
    return None
```

We find:

```
e = 308776508606152118670230312260475727067
p = 885155638896815121721984702668159252469789007
q = 1396480793192855813962038749872058535698968723
```

Verification:

```
p * q == n  ✅
```

---

### Step 4: Recover Private Key

Since we already know `mod_phi`, computing `d` is trivial:

```python
from Crypto.Util.number import inverse

d = inverse(e, mod_phi)
```

---

### Step 5: Decrypt Ciphertext

```python
pt = pow(c, d, n)
print(long_to_bytes(pt).decode())
```

Output:

```
Blitz{Cust0m_RSA_OMGGG}
```

---

## Full Exploit Script

```python
from Crypto.Util.number import *
from sympy import divisors
from itertools import combinations

mod_phi = 381679521901481226602014060495892168161810654344421566396411258375972593287031851626446898065545609421743932153327689119440405912
n = 1236102848705753437579242450812782858653671889829265508760569425093229541662967763302228061
c = 337624956533508120294617117960499986227311117648449203609049153277315646351029821010820258

def get_primes(modulus: int):
    primes = []
    for i in divisors(modulus):
        if isPrime(i + 1):
            primes.append(i + 1)
    return primes

def keep_valid_primes(primes):
    valid_lengths = {127, 128, 149, 150}
    return [p for p in primes if p.bit_length() in valid_lengths]

def find_pqe(primes, mod_phi):
    for p, q, r in combinations(primes, 3):
        if (p - 1) * (q - 1) * (r - 1) == mod_phi:
            return p, q, r
    return None

# Generate candidates
primes_list = get_primes(mod_phi)
valid_primes = keep_valid_primes(primes_list)

# Find correct triple
e, p, q = find_pqe(valid_primes, mod_phi)

assert p * q == n

# Recover private key
d = inverse(e, mod_phi)

# Decrypt
pt = pow(c, d, n)
print("Decrypted flag is:", long_to_bytes(pt).decode())
```

---

## 5) Why This Broke

This RSA construction fails because:

- It leaks `(p-1)(q-1)(e-1)`
- That completely reveals structure of all three primes
- Factoring `mod_phi` gives direct path to recovering `p`, `q`, and `e`
- Once `(p, q)` are known, RSA collapses

This is fundamentally insecure.

---

## 6) Final Flag

```
Blitz{Cust0m_RSA_OMGGG}
```

---

## 7) Key Takeaways

- Never leak totient-like values.
- RSA security depends entirely on hiding `p` and `q`.
- Even leaking `(p−1)` structure can destroy the system.
- Custom RSA modifications almost always introduce fatal weaknesses.
- If additional values are printed — always analyze them first.

---

## 8) Quick Crypto Checklist

- If any φ-related value is given → attack it  
- If exponent is unusual → inspect structure  
- Always analyze algebra before brute force  
- RSA breaks when number theory assumptions fail  

---