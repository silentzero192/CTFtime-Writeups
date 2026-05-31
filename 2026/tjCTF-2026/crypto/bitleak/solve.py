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

print(f"n bits = {n.bit_length()}")

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

    if (i + 1) % 64 == 0:
        print(f"[{i+1}/{bits}]")

m = (n * F + (1 << bits) - 1) >> bits
flag = long_to_bytes(m)
print(f"flag: {flag.decode()}")

r.close()
