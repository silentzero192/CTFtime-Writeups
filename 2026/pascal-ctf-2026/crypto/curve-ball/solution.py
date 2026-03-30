#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import inverse
from random import randint

# =========================
# Server info
# =========================
HOST = "curve.ctf.pascalctf.it"
PORT = 5004

# =========================
# Curve parameters
# =========================
p = 1844669347765474229
n = 1844669347765474230  # p + 1 (supersingular)


# =========================
# Point class (same logic as server)
# =========================
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_inf(self):
        return self.x is None

    def __add__(self, other):
        if self.is_inf():
            return other
        if other.is_inf():
            return self
        if self.x == other.x and (self.y + other.y) % p == 0:
            return Point(None, None)

        if self.x == other.x:
            s = (3 * self.x * self.x) * inverse(2 * self.y, p) % p
        else:
            s = (other.y - self.y) * inverse(other.x - self.x, p) % p

        xr = (s * s - self.x - other.x) % p
        yr = (s * (self.x - xr) - self.y) % p
        return Point(xr, yr)

    def __rmul__(self, k):
        r = Point(None, None)
        a = self
        while k > 0:
            if k & 1:
                r = r + a
            a = a + a
            k >>= 1
        return r


# =========================
# Chinese Remainder Theorem
# =========================
def crt(remainders, moduli):
    M = 1
    for m in moduli:
        M *= m

    result = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        result += r * Mi * inverse(Mi, m)

    return result % M


# =========================
# Connect to server
# =========================
io = remote(HOST, PORT)

# wait for first menu
io.recvuntil(b"> ")

# =========================
# Small factors of n = p + 1
# =========================
small_factors = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]

remainders = []
moduli = []

for q in small_factors:
    k = n // q

    # ---- find point of order q ----
    while True:
        x = randint(2, p - 2)
        rhs = (x**3 + 1) % p

        # sqrt mod p (p ≡ 1 mod 4)
        y = pow(rhs, (p + 1) // 4, p)

        P = Point(x, y)
        R = k * P

        if not R.is_inf():
            break

    # ---- ask oracle: 1 * R ----
    io.sendline(b"2")
    # io.recvuntil(b"k:")
    # io.sendline(b"1")
    # io.recvuntil(b"P")
    # io.sendline(f"({R.x},{R.y})".encode())

    # ---- read until Result ----
    # while True:
    #     line = io.recvline().decode().strip()
    #     if line.startswith("Result:"):
    #         break

    # if "infinity" in line:
    #     s_mod = 0
    # else:
    #     data = line.split("(")[1].split(")")[0]
    #     xr, yr = map(int, data.split(","))
    #     S = Point(xr, yr)

    #     # brute-force secret mod q
    #     for i in range(q):
    #         if i * R == S:
    #             s_mod = i
    #             break

    # remainders.append(s_mod)
    # moduli.append(q)

    # log.success(f"secret ≡ {s_mod} (mod {q})")

    # # sync back to menu
    # io.recvuntil(b"> ")

# =========================
# Recover full secret
# =========================
secret = crt(remainders, moduli)
log.success(f"Recovered secret = {hex(secret)}")

# =========================
# Submit secret and get flag
# =========================
io.sendline(b"1")
io.recvuntil(b"hex")
io.sendline(hex(secret).encode())

io.interactive()
