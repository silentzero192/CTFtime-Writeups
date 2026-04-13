# Portobelo

## Challenge Info

- **Name**: `portobelo`
- **Category**: `crypto`
- **Description**: `The treasure is locked behind a key exchange. Recover it.`

## TL;DR

The server exposes a `QUERY <A>` oracle that returns

```text
RESULT <j_invariant(A)> <ops_count> <trace(A)>
```

The `trace(A)` value is a degree-73 polynomial in `A` whose coefficients are the secret key entries, except for one hidden "poisoned" index that is skipped entirely.

That means:

1. We can query the oracle at 74 distinct non-singular points.
2. Interpolate the leaked polynomial modulo `p`.
3. Recover every non-poisoned secret-key coefficient directly.
4. Use `ops_count = sum(abs(secret_key[i]))` to recover the magnitude of the missing coefficient.
5. Try the remaining candidate positions and validate them with the provided AES-GCM ciphertext and tag.

This recovers the secret key and decrypts the flag:

```text
RS{504_1s_7smo0th_s0_th3_0rb1t_h4s_n1n3}
```

---

## Files

- [server.py](./server.py)
- [params.json](./params.json)
- [solve.py](./solve.py)

---

## Initial Analysis

The server sends public parameters and an encrypted flag at connection time:

```text
PORTOBELO v1.0
PARAMS <base64-encoded json>
ENCRYPTED_FLAG <ct> <nonce> <tag>
READY
```

The interesting handler is `handle_query()` in `server.py`:

```python
ops_count = params["ops_count"]
j_inv = j_invariant(query_A, p)
trace = trace(query_A, params["secret_key"], params["primes"], p,
                            skip_index=params["poisoned_index"])
self.write_line(f"RESULT {j_inv} {ops_count} {trace}")
```

The three returned values are:

- `j_inv`: the Montgomery `j`-invariant of the queried curve.
- `ops_count`: a constant equal to `sum(abs(e) for e in secret_key)`.
- `trace`: a polynomial evaluation derived from the secret key.

Only `trace` and `ops_count` are useful for the break.

---

## The Core Bug

The `trace()` function is:

```python
def trace(query_A, secret_key, primes, p, skip_index=-1):
    A_pow = 1
    trace = 0
    for i in range(len(primes)):
        if i != skip_index:
            trace = (trace + secret_key[i] * A_pow) % p
        A_pow = A_pow * query_A % p
    return trace
```

This is exactly the polynomial

```text
f(A) = sum(secret_key[i] * A^i) mod p, for all i except the poisoned index
```

So the server is leaking evaluations of a fixed polynomial of degree at most 73.

Let:

```text
c_i = secret_key[i] for i != poisoned_index
c_k = 0            for the poisoned index k
```

Then the oracle is returning:

```text
f(A) = c_0 + c_1 A + c_2 A^2 + ... + c_73 A^73 mod p
```

If we obtain 74 evaluations at distinct points, we can solve for all 74 coefficients.

That is the full break.

---

## Why Interpolation Works

There are 74 primes in `params.json`, so the secret key has length 74 and `f(A)` has at most 74 coefficients.

We query the service at:

```text
A in {0, 1, 3, 4, 5, ..., 74}
```

We skip `A = 2` because the server rejects singular curves:

```python
if pow(query_A, 2, p) == 4 % p:
    self.write_line("Singular curve (A^2 = 4)")
    return
```

Since `2^2 = 4`, `A = 2` is invalid. Every other small value in that set is fine.

For each chosen `A = x_j`, we get:

```text
f(x_j) = sum(c_i * x_j^i) mod p
```

This gives a Vandermonde linear system:

```text
M * c = y mod p
```

where:

- `M[j][i] = x_j^i mod p`
- `c = (c_0, ..., c_73)`
- `y[j] = f(x_j)`

Because the `x_j` are distinct modulo `p`, the Vandermonde matrix is invertible, so Gaussian elimination modulo `p` recovers every coefficient.

---

## What We Recover From the Oracle

After interpolation and center-lifting from modulo `p` back to small signed integers, the recovered coefficient vector is:

```python
[0, 0, 0, 0, 0, 1, 0, 0, -2, 1, 0, 0, 1, 3, -3, 2, 4, -1, 0, -3, 0,
 -2, 1, -3, 0, 2, -1, 0, 1, 3, 0, 2, 4, 4, 1, 1, 4, 0, -1, -1, -1,
 0, 0, 0, -4, -1, 0, 1, -1, 4, 0, 2, 0, 0, -1, 0, -3, 0, 1, -1, 0,
 -2, -3, 1, -1, -3, 0, 3, 1, 0, 0, 0, 0, 0]
```

This is almost the full secret key, except the poisoned index has been replaced by `0`.

At this point there is one ambiguity:

- some entries are genuinely zero
- one zero entry is fake and corresponds to the hidden coefficient

---

## Recovering the Missing Magnitude

The server also leaks:

```python
params["ops_count"] = sum(abs(e) for e in params["secret_key"])
```

From the recovered coefficients we compute:

```text
sum(abs(recovered_coeffs)) = 86
ops_count = 89
```

So the missing coefficient must satisfy:

```text
abs(missing_value) = 89 - 86 = 3
```

Now the unknown is reduced to:

- which zero index is the poisoned one
- whether its value is `+3` or `-3`

---

## Using AES-GCM as the Final Oracle

We do not actually need to recompute the public isogeny action to identify the missing position.

The server already gives us:

- `flag_ct`
- `flag_nonce`
- `flag_tag`

The KDF is completely public:

```python
def kdf(secret_key, poly_coeffs, gen_coeffs):
    sk_bytes = bytes([e + 127 for e in secret_key])
    h = hashlib.shake_256(sk_bytes)
    ...
    return bytes(a ^ b for a, b in zip(derived, squeeze))
```

So for each candidate:

1. Insert `+3` or `-3` at one of the zero positions.
2. Recompute the AES key with the same `kdf()`.
3. Attempt `AES-GCM decrypt_and_verify()`.

Only the correct secret key will produce a valid authentication tag.

This is much cheaper than trying to recompute and compare the full public group action for every candidate.

There were 31 zero positions in the interpolated vector, so this leaves only:

```text
31 * 2 = 62
```

candidate keys to test locally.

The correct candidate is:

```text
poisoned_index = 73
secret_key[73] = -3
```

---

## Full Exploit Strategy

### 1. Connect to the service

Grab the public parameters and encrypted flag.

### 2. Query 74 times

Send:

```text
QUERY 0
QUERY 1
QUERY 3
...
QUERY 74
```

skipping `2`.

### 3. Build the linear system

For each point `x`:

```text
sum(c_i * x^i) = trace(x) mod p
```

### 4. Solve for the leaked coefficients

Use modular Gaussian elimination on the Vandermonde matrix.

### 5. Recover the missing absolute value

Use:

```text
abs(missing) = ops_count - sum(abs(leaked_coeffs))
```

### 6. Test the remaining candidates

For each zero coefficient position and sign choice:

- rebuild candidate secret key
- run the public `kdf()`
- try `AES-GCM decrypt_and_verify()`

### 7. Read the flag

The only candidate that verifies yields the plaintext flag.

---

## Solver

The final exploit script is [solve.py](./solve.py).

Run it with:

```bash
python solve.py
```

Example output:

```text
ops_count = 89
missing_abs = 3
zero coefficient indices = [0, 1, 2, 3, 4, 6, 7, 10, 11, 18, 20, 24, 27, 30, 37, 41, 42, 43, 46, 50, 52, 53, 55, 57, 60, 66, 69, 70, 71, 72, 73]
matched poisoned index 73 with value -3
RS{REDACTED}
```

---

## Why The Challenge Is Vulnerable

The intended hard problem is the hidden key exchange / isogeny action.

But the implementation exposes a direct linear leakage of the secret key:

```text
trace(A) = sum(secret_key[i] * A^i) mod p
```

This turns the private key recovery problem into plain polynomial interpolation over a finite field.

Once that happens:

- the isogeny machinery is no longer protecting the secret
- the hidden coefficient is the only remaining obstacle
- `ops_count` leaks its magnitude
- AES-GCM leaks correctness of the full reconstructed key through tag verification

So the cryptographic hardness is bypassed entirely by an algebraic side channel in the oracle design.

---

## Final Flag

```text
RS{504_1s_7smo0th_s0_th3_0rb1t_h4s_n1n3}
```
