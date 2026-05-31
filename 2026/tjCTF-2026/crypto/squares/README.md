# Squares

**Category:** Crypto  
**Points:** ~  
**Flag:** `tjctf{m4tr1c3s_4r3_4ll_y0u_n33d}`

---

## Description

> A system defines a quadratic function over a finite field:
> 
> \[
> H(x) = x^T M x - 2c^T x \pmod{p}
> \]
> 
> The secret input \(x\) is a stationary point of \(H(x)\).
> 
> Recover \(x\) and decode it to obtain the flag.

---

## Given

```
p = 257
M = 52×52 matrix over GF(p)
c = length-52 vector over GF(p)
```

File: [`out.txt`](./out.txt)

---

## Solution

### 1. Deriving the stationary point condition

For a quadratic form \(H(x) = x^T M x - 2c^T x\), the gradient is:

\[
\nabla H(x) = (M + M^T)x - 2c
\]

A **stationary point** satisfies \(\nabla H(x) = 0\), i.e.:

\[
(M + M^T)x \equiv 2c \pmod{p}
\]

Let \(A = M + M^T\). This is a symmetric matrix over \(\mathbb{F}_{257}\).

### 2. Solving the linear system

We need to solve:

\[
A x = 2c \quad \text{over } \mathbb{F}_{257}
\]

This is a straightforward linear system — 52 equations in 52 unknowns. Using SageMath:

```python
F = GF(257)
M = matrix(F, M_data)
c = vector(F, c)

A = M + M.T
b = 2 * c

x = A.solve_right(b)
```

### 3. Decoding the flag

The solution vector \(x\) contains integer values in \([0, 256]\). Interpreting each as an ASCII character:

```python
flag = ''.join(chr(int(xi)) for xi in x)
print(flag)
```

Output:

```
tjctf{m4tr1c3s_4r3_4ll_y0u_n33d}
```

The trailing spaces are padding to make the vector length 52.

---

**Flag:** `tjctf{m4tr1c3s_4r3_4ll_y0u_n33d}`
