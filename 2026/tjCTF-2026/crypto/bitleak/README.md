# bitleak — RSA Parity Oracle Attack

**Category:** Crypto  
**Challenge:** bitleak  
**Flag:** `tjctf{parity_isnt_privacy}`  
**Solves:** (your count here)

---

## Challenge Description

> Our security monitor only ever tips us off about the parity of RSA decryptions. Turns out "even or odd" isn't much of a secret. Can you recover the message one bit at a time?

You're given a server (`tjc.tf:31001`) that acts as an RSA decryption oracle — but it only tells you whether the decrypted plaintext is even or odd (i.e., the least significant bit). You have up to 2100 queries to recover the flag.

---

## The Vulnerability — RSA LSB Oracle

The server (`server.py`) does the following:

1. Generates two 256-bit primes $p, q$ and sets $n = p \cdot q$ (512-bit RSA).
2. Encrypts the flag: $c = m^e \bmod n$ with $e = 65537$.
3. Gives you $n, e, c$.
4. Lets you submit up to 2100 ciphertexts. For each, it returns $\text{decrypt}(c') \bmod 2$ — the **least significant bit** of the decrypted message.

The core oracle code:

```python
parity = pow(candidate, d, n) & 1
print(f"lsb = {parity}")
```

This is a textbook **RSA LSB (parity) oracle attack**. The homomorphic property of RSA lets us multiply the plaintext by chosen factors:

$$E(m_1) \cdot E(m_2) \bmod n = E(m_1 \cdot m_2 \bmod n)$$

If we send $c' = c \cdot 2^e \bmod n$, the server decrypts:

$$\text{decrypt}(c') = 2m \bmod n$$

Now, the LSB of $(2m \bmod n)$ tells us:

- **LSB = 0:** $2m < n$ → $m < n/2$ (the message is in the lower half)
- **LSB = 1:** $2m \ge n$ → $m \ge n/2$ (the message wrapped around; it's in the upper half)

Each query reveals one bit of the binary expansion of $m/n$.

---

## The Attack

### Bit Extraction via Binary Fraction

Let $k = \text{bitlen}(n)$. For the $i$-th query ($1 \le i \le k$), we send:

$$c_i = c \cdot (2^e)^i \bmod n$$

The server decrypts to $2^i \cdot m \bmod n$, and its LSB is:

$$b_i = \left\lfloor \frac{2^i \cdot m}{n} \right\rfloor \bmod 2$$

This is exactly the $i$-th bit of the binary fraction $m/n$. After $k$ queries, we've accumulated:

$$F_k = \sum_{i=1}^{k} b_i \cdot 2^{k-i} = \left\lfloor \frac{2^k \cdot m}{n} \right\rfloor$$

### Message Recovery

Once we have $F_k$, we know:

$$F_k \le \frac{2^k \cdot m}{n} < F_k + 1$$

Since $n/2^k < 1$ (we queried at least $\lceil \log_2 n \rceil$ times), there's exactly one integer $m$ satisfying:

$$\frac{n \cdot F_k}{2^k} \le m < \frac{n \cdot (F_k + 1)}{2^k}$$

We recover it via ceiling division:

$$m = \left\lceil \frac{n \cdot F_k}{2^k} \right\rceil = \frac{n \cdot F_k + 2^k - 1}{2^k}$$

### Efficiency — Pipelining

Each query requires the server to compute $\text{pow}(c', d, n)$. With ~512 queries, the total time is dominated by network round-trips **unless we pipeline**.

The key observation: **the ciphertexts don't depend on the oracle responses**. Each step just multiplies by $2^e \bmod n$:

$$c_{i+1} = c_i \cdot 2^e \bmod n$$

So we can precompute all ciphertexts, send them in a burst, and read all responses sequentially.

However, in practice, aggressive pipelining can overflow the server's output buffer. The sweet spot is using `sendlineafter`, which naturally paces the requests at server speed — still fast since we never wait for extra round-trips beyond what the server's computation requires.

---

## The Solve Script

```python
from pwn import *
from Crypto.Util.number import long_to_bytes

HOST = "tjc.tf"
PORT = 31001

r = remote(HOST, PORT)

r.recvuntil(b"n = ")
n = int(r.recvline().strip())
r.recvuntil(b"e = ")
e = int(r.recvline().strip())
r.recvuntil(b"ciphertext = ")
c = int(r.recvline().strip())

bits = n.bit_length()
mult = pow(2, e, n)

F = 0
cur_c = c

for i in range(bits):
    cur_c = (cur_c * mult) % n
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"ciphertext = ", str(cur_c).encode())
    r.recvuntil(b"lsb = ")
    parity = int(r.recvline().strip())
    F = (F << 1) | parity

# m = ceil(n * F / 2^bits)
m = (n * F + (1 << bits) - 1) >> bits
flag = long_to_bytes(m)
print(f"flag: {flag.decode()}")
r.close()
```

---

## Why This Works

RSA's homomorphism lets us manipulate the plaintext under encryption:

$$E(m) \cdot E(r)^e \bmod n = E(m \cdot r \bmod n)$$

By choosing $r = 2, 4, 8, \dots, 2^k$, each query shifts the plaintext left by one bit. The LSB of the shifted value tells us whether a wrap-around occurred — which is exactly the next bit of $m/n$ in binary.

After $\lceil \log_2 n \rceil = 512$ queries, we've effectively performed a binary search over the $[0, n)$ interval, narrowing down the message to a unique value.

---

## Preventing This Attack

The fix is simple: **never expose a raw decryption oracle**. Use OAEP (Optimal Asymmetric Encryption Padding) or another secure padding scheme. OAEP ensures that even a single bit of decrypted output reveals nothing useful, and it makes the decryption oracle non-malleable.

The challenge name "bitleak" and the flag `tjctf{parity_isnt_privacy}` reference the classic paper *"Why Plaintext RSA Encryption Does Not Provide Semantic Security"* and the well-known result that **parity is a total break** for textbook RSA.
