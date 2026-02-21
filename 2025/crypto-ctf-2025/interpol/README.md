# CTF Writeup

**Challenge Name:** Interpol  
**Event:** Crypto CTF 2025  
**Category:** Cryptography  
**Difficulty:** Medium  
**Time Spent:** ~45 minutes  

---

## 1) Goal

We were given:

- `interpol.sage` (challenge generator)
- `output.raw` (serialized polynomial)
- A hint:  
  > Only brute force won't crack Interpol! Its massive polynomial guards the flag fiercely.

The objective was to recover the original flag from a large polynomial.

---

## 2) Understanding the Challenge

From `interpol.sage`:

```python
poly = QQ['x'].lagrange_polynomial(DATA).dumps()
```

The author:

1. Generates a set of points `DATA`
2. Builds a **Lagrange interpolation polynomial over ℚ**
3. Serializes it into `output.raw`

So we are given a polynomial `P(x)` such that:

```
P(x_i) = y_i
```

for all points in `DATA`.

---

## 3) How Points Are Constructed

The crucial logic:

```python
if randint(0, 1):
    return True, [
        (
            -(1 + (19*n - 14) % len(flag)),
            ord(flag[(63 * n - 40) % len(flag)])
        )
    ]
```

This means:

For each flag character:

- The x-coordinate is a **negative integer**
- The y-coordinate is the ASCII value of the flag character
- The position mapping is scrambled via modular arithmetic

So:

```
x = negative integers
y = ASCII(flag character)
```

Other random points are also added, but:

- They use rational numbers
- They do NOT lie on negative consecutive integers
- They serve as noise

---

## 4) Key Insight

The actual flag points are:

```
P(-1), P(-2), P(-3), ...
```

Because those are the special negative positions inserted during generation.

The random noise points do not follow this pattern.

Therefore:

If we evaluate the polynomial at:

```
x = -1, -2, -3, ...
```

We can extract flag characters.

---

## 5) Exploitation Strategy

### Step 1 — Load Polynomial

```python
R.<x> = QQ[]

with open("output.raw", "rb") as f:
    poly = loads(f.read())
```

---

### Step 2 — Extract Valid Negative Points

We evaluate:

```
poly(-1), poly(-2), poly(-3), ...
```

Until result is no longer:

- An integer
- Between 0 and 255

```python
flag_points = []
i = 1
while True:
    x_val = -i
    y_val = poly(x_val)
    if y_val in ZZ and 0 <= y_val <= 255:
        flag_points.append((x_val, y_val))
        i += 1
    else:
        break
```

This gives:

```
Flag length: 53
```

So the flag is 53 characters long.

---

## 6) Understanding the Index Scrambling

Original mapping:

```
x_index = -(1 + (19*n - 14) % L)
y_index = (63*n - 40) % L
```

We must reverse this permutation.

### Solve:

We want to map:

```
i → correct flag position
```

Using modular inverse:

```python
inv19 = inverse_mod(19, L)
a = (63 * inv19) % L
b = (a * 14 - 40) % L
```

Now we reconstruct:

```python
flag_chars = [0]*L
for x_val, y_val in flag_points:
    i = -x_val - 1
    k = (a*i + b) % L
    flag_chars[k] = chr(y_val)

flag = ''.join(flag_chars)
```

---

## 7) Full Solver

```python
R.<x> = QQ[]

with open("output.raw", "rb") as f:
    poly = loads(f.read())

flag_points = []
i = 1
while True:
    x_val = -i
    y_val = poly(x_val)
    if y_val in ZZ and 0 <= y_val <= 255:
        flag_points.append((x_val, y_val))
        i += 1
    else:
        break

L = len(flag_points)
print(f"Flag length: {L}")

inv19 = inverse_mod(19, L)
a = (63 * inv19) % L
b = (a * 14 - 40) % L

flag_chars = [0]*L
for x_val, y_val in flag_points:
    i = -x_val - 1
    k = (a*i + b) % L
    flag_chars[k] = chr(y_val)

flag = ''.join(flag_chars)
print(flag)
```

---

## 8) Final Flag

```
CCTF{7h3_!nTeRn4t10naL_Cr!Min41_pOlIc3_0r9An!Zati0n!}
```

---

## 9) Why This Works

- Lagrange interpolation guarantees the polynomial fits all points.
- The flag points are deliberately placed at structured negative integers.
- Random noise points are irrelevant.
- Evaluating the polynomial reveals the exact y-values.
- Modular arithmetic must be inverted to reorder characters.

---

## 10) Key Lessons

- Polynomial interpolation over ℚ is fully reversible if the polynomial is known.
- Serialization of symbolic objects leaks everything.
- Hidden structure in x-coordinates can betray embedded data.
- Modular permutations are easily invertible using modular inverses.
- “Massive polynomial” ≠ security.

---

## 11) Core Concept

This challenge is fundamentally:

> Data hiding inside interpolation points.

If you know the polynomial, you know **every point it interpolates**.

Security was assumed to come from polynomial size —  
but mathematical determinism makes it fully recoverable.

---
