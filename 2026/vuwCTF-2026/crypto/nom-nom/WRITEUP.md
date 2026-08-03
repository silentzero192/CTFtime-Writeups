# VuwCTF 2026 — Crypto / nom-nom

> **Challenge**
> - **Category:** Crypto
> - **Name:** nom-nom
> - **Description:** *A hungry moose ate my flag. It looked pretty hungry so I don't blame it, but I really need that flag back.*
> - **Flag format:** `VuwCTF{}`

## Files

| File           | Description                                             |
| -------------- | ------------------------------------------------------- |
| `nom-nom.sage` | Server-side encryption script that generated the cipher |
| `nom-nom.txt`  | The provided ciphertext parameters                      |
| `solve.py`     | Solver                                                 |

## Challenge source

```python
# nom-nom.sage
import os

e = 3

p = random_prime(2^1024-1, lbound=2^1023)
assert p % e != 1
q = random_prime(2^1024-1, lbound=2^1023)
assert q % e != 1
n = p * q

flag_inner = os.environ["FLAG"].encode()
assert len(flag_inner) == 16
flag = b"VuwCTF{" + flag_inner + b"}"

c_flag_inner = pow(int.from_bytes(flag_inner), e, n)
c_flag = pow(int.from_bytes(flag), e, n)

print(f"{e=}")
print(f"{n=}")
print(f"{c_flag_inner=}")
print(f"{c_flag=}")
```

And the output:

```
e=3
n=23707197993895447078364393544593554409233601526592962831150463673882355911189113424097140679667445266559285662062727613402947013259193813854615059925745985883600330558655591483535818026899052693949472719902725265771947750247680482484310001936745678989301667779643544411763555413872585114988172092331518732712737462592655280638153797220147296945886923465458551635627915985349482172969999726989004490603248619513821962339554823985525358068948321846933722030955885966992329945938232221539839089056620137940420510534597106516128950051183728843883585411229295171738507117378123853243631956542689544260936869040031601145971
c_flag_inner=1133267644716881236728907279798730177484710508597335845998937053548163164206075334320272976072123221745873552889781
c_flag=9527654200947120851835022226909710255198929202034098647062624660849299291035084452413105331220565070077932744859276876935374540635318259816034238658466105223691964150991973
```

## TL;DR

The public exponent is the tiny value `e = 3`, while the plaintexts are small
enough that `plaintext^3 < n`. The modular exponentiation therefore never
"wraps around" the modulus — the ciphertexts are **exact integer cubes**.
Recover the plaintexts with a simple **integer cube root**:

```
flag_inner = cuberoot(c_flag_inner)   →  NomPolynomialNom
flag       = cuberoot(c_flag)         →  VuwCTF{NomPolynomialNom}
```

---

## Background: why small exponents are dangerous

RSA encryption computes

```
c = m^e mod n
```

where `m` is the numeric representation of the plaintext and `e` is the public
exponent. The whole point of the `mod n` is to keep the result in a bounded
range. But if the message is so small that `m^e` is *still smaller than `n`*,
then the modular reduction is a no-op and we simply have

```
c = m^e            (an exact integer, no mod applied)
```

For `e = 3`, that means `c` is a perfect cube, and `m` is its cube root.

### Sizing the numbers

The modulus is 2048 bits. The messages:

| Message      | Byte size | Bit size        | `message^3` bit size |
| ------------ | --------- | --------------- | -------------------- |
| `flag_inner` | 16 bytes  | up to 128 bits  | up to **384 bits**   |
| `flag`       | 23 bytes  | up to 184 bits  | up to **552 bits**   |

Both `384` and `552` are far below the modulus size (`2048`), so in both cases

```
message^3 < n
```

and the attack works on the whole flag — we don't even need the helper
`c_flag_inner`.

---

## Attack

### 1. Verify the ciphertext is a perfect cube

We compute the integer cube root (a fast, exact operation) and check it
re-cubes to the ciphertext:

```python
from gmpy2 import iroot

m_flag_inner, exact1 = iroot(c_flag_inner, 3)
m_flag,       exact2 = iroot(c_flag, 3)

assert exact1 and exact2          # both are perfect cubes
```

### 2. Convert the integers back to bytes

```python
flag_inner = m_flag_inner.to_bytes(16, "big")
flag       = m_flag.to_bytes(24, "big")     # "VuwCTF{" + 16 bytes + "}"
```

### 3. Sanity check against the challenge code

The challenge asserts `flag = b"VuwCTF{" + flag_inner + b"}"`, which we can
verify directly from our recovered values.

---

## Full solution

```python
#!/usr/bin/env python3
import gmpy2
from pathlib import Path

def integer_cuberoot(n):
    root, exact = gmpy2.iroot(n, 3)
    assert exact, "ciphertext is not an exact cube!"
    return int(root)

params = {}
for line in Path("nom-nom.txt").read_text().splitlines():
    k, _, v = line.partition("=")
    if k.strip():
        params[k.strip()] = int(v.strip())

e   = params["e"]
n   = params["n"]
c1  = params["c_flag_inner"]
c2  = params["c_flag"]

m1 = integer_cuberoot(c1)
m2 = integer_cuberoot(c2)

flag_inner = m1.to_bytes(16, "big")
flag       = m2.to_bytes(24, "big")

assert pow(m1, e, n) == c1
assert pow(m2, e, n) == c2
assert flag == b"VuwCTF{" + flag_inner + b"}"

print(flag.decode())          # VuwCTF{NomPolynomialNom}
```

### Output

```
[+] flag_inner bytes : b'NomPolynomialNom'
[+] flag            : VuwCTF{NomPolynomialNom}
```

---

## Flag

```
VuwCTF{NomPolynomialNom}
```

---

## Mitigation / takeaway

- Never use such a small public exponent (`e = 3`) without proper **padding**
  (e.g. RSA-OAEP) or *at least* ensuring `m^e >> n`.
- This is the classic **low-exponent attack** / *Håstad's broadcast attack* in
  its simplest (single-message, no-padding) form. When `m^e < n`, RSA is
  trivially invertible.
- The same bug also appears when the plaintext is known to lie in a small
  subset — that is what makes small-message attacks so common in CTFs.
