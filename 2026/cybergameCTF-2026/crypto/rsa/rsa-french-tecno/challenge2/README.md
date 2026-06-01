# RSA French Technology - Writeup

**Challenge Name:** `rsa french technology`  
**Platform:** `CybergameCTF 2026`  
**Category:** `Crypto`  

## 1) Goal (What was the task?)

The challenge provided a small RSA encryption script and an output file containing `c`, `n`, and `e`. The goal was to recover the hidden plaintext flag in the format `SK-CERT{...}`.

Success meant extracting the exact flag string that was encrypted by the challenge code.

## 2) Key Clues (What mattered?)

- The source file was `main.py`, and it used raw RSA with no padding.
- The output values were stored in `out.txt`.
- `p` and `q` were only `192` bits each, so `n` was about `384` bits total.
- The hint said: `flag may be longer then you expect`.
- The flag format was known in advance: `SK-CERT{...}`.
- The code used `bytes_to_long(flag.encode())`, which means the entire flag string was converted directly into one big integer before encryption.

## 3) Plan (Your first logical approach)

- Read the challenge code first to understand exactly how RSA was implemented.
- Check whether the modulus was small enough to factor quickly.
- If factoring worked, compute the RSA private key and decrypt the ciphertext.
- If the decrypted bytes did not look like a flag, use the hint and the known flag format to figure out what went wrong.

## 4) Steps (Clean execution)

### 1. Read the provided code

The core of the challenge was:

```python
from Crypto.Util.number import bytes_to_long, getPrime

flag = ""

m = bytes_to_long(flag.encode())
p = getPrime(192)
q = getPrime(192)

n = p * q
e = 65537

c = pow(m, e, n)
```

Important observations:

- This is textbook RSA.
- There is no padding.
- The flag is turned into a large integer directly.
- The primes are very small for RSA: only `192` bits each.

That immediately suggested that factoring `n` would probably be enough to break the scheme.

### 2. Inspect the public values

From `out.txt `:

```text
c:  5740196029944570285461595789387642615026206835758048500685342416498085007060475130355254601538690350792607830802905
n:  17898028240830814136434787407852442663239728391134776310533753763258523791465145947321086853292608375964370070398263
e:  65537
```

`n` is only about `383` bits long, which is tiny for RSA.

That means:

- Factoring it is realistic.
- The largest plaintext that can fit without wrapping modulo `n` is only about `48` bytes.

This size observation became very important later.

### 3. Factor the modulus

I checked the modulus in FactorDB and it already had the factorization:

```text
p = 3471990687824593680273251255463630853556792715805318789409
q = 5154975876978800665290208266910928152604080453168333003607
```

Now the RSA private key can be rebuilt normally:

```python
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
```

### 4. Decrypt the ciphertext

With the private exponent:

```python
m = pow(c, d, n)
```

At this point, I expected to see the flag bytes. Instead, the decrypted bytes looked random and did not resemble `SK-CERT{...}`.

That told me the solve was not just “factor and decrypt”.

### 5. Understand why the decrypted bytes looked wrong

The crucial detail was the hint:

```text
flag may be longer then you expect
```

RSA encryption computes:

```text
c = m^e mod n
```

If the original plaintext integer `m` is larger than `n`, RSA does **not** preserve the whole number. It only preserves `m mod n`.

So even after correct decryption, what we recover is:

```text
m' = m mod n
```

not necessarily the original full flag integer.

That perfectly explains the random-looking decryption result.

### 6. Compare the modulus size to the possible flag length

The modulus was only `48` bytes wide, but the hint suggested the flag was longer than normal.

Since the flag format starts with `SK-CERT{` and ends with `}`, I modeled the flag as:

```text
flag = b"SK-CERT{" + middle + b"}"
```

If the total flag length is greater than `48` bytes, then the plaintext integer is larger than `n`, and encryption wraps it modulo `n`.

So the real task became:

- Recover the missing middle part using the known prefix, known suffix, and the decrypted residue.

### 7. Turn the problem into modular arithmetic

Let:

```text
residue = pow(c, d, n)
```

and let the unknown flag be:

```text
flag = prefix || middle || suffix
```

As an integer, that is:

```text
flag_int = prefix * 256^(len(middle)+len(suffix)) + middle * 256^(len(suffix)) + suffix
```

Since RSA gave us the plaintext modulo `n`, we know:

```text
flag_int mod n = residue
```

Rearranging gives:

```text
middle * 256^(len(suffix)) = residue - prefix_term - suffix   (mod n)
```

Because `256` is invertible modulo odd RSA moduli, I could solve for `middle` once I guessed the total length.

That means I did **not** need to brute-force the flag characters. I only needed to:

- try candidate flag lengths,
- solve directly for `middle`,
- check whether the result is printable ASCII,
- re-encrypt the candidate and confirm it matches `c`.

## 5) Solution Summary (What worked and why?)

The first half of the challenge was standard weak RSA: the modulus was small enough to factor, so the private key could be reconstructed easily. The interesting twist was that decrypting the ciphertext did not immediately reveal the flag, because the original plaintext integer was longer than the modulus and had wrapped modulo `n`.

The hint pointed exactly to that issue. Once I realized the flag was larger than `n`, I treated the decrypted value as `flag mod n`, used the known `SK-CERT{...}` structure, and solved for the unknown middle section for different candidate lengths. Re-encryption confirmed the correct flag.

## 6) Flag

```text
SK-CERT{f4c70r1ng_5m4ll_53m1_pr1m35_571ll_34sy_45_b3f0r3}
```

## 7) Lessons Learned (make it reusable)

- Textbook RSA without padding is fragile, especially when the modulus is small.
- Factoring is not always the end of the challenge; sometimes the real trick is what the plaintext representation is doing.
- Always compare plaintext size against modulus size in RSA challenges.
- If a flag format is known, it can turn a difficult modular recovery problem into a very manageable one.

## 8) Personal Cheat Sheet (optional, but very useful)

- `FactorDB` -> quick check for whether an RSA modulus has already been factored.
- `pow(c, d, n)` -> standard RSA decryption once `d` is known.
- `pow(a, -1, n)` -> modular inverse in Python 3.
- RSA check: if decrypted bytes look random, ask whether the original message may have been larger than `n`.
- Crypto pattern: if the challenge gives a known prefix like `flag{` or `SK-CERT{`, try modeling the plaintext structure algebraically instead of brute-forcing characters.
