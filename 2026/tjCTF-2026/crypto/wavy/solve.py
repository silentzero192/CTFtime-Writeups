from pathlib import Path
from Crypto.Util.number import long_to_bytes

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

def mat_mul(A, B, p):
    return [
        [(A[0][0]*B[0][0] + A[0][1]*B[1][0]) % p, (A[0][0]*B[0][1] + A[0][1]*B[1][1]) % p],
        [(A[1][0]*B[0][0] + A[1][1]*B[1][0]) % p, (A[1][0]*B[0][1] + A[1][1]*B[1][1]) % p]
    ]

def mat_pow(M, n, p):
    result = [[1, 0], [0, 1]]
    base = M
    while n > 0:
        if n & 1:
            result = mat_mul(result, base, p)
        base = mat_mul(base, base, p)
        n >>= 1
    return result

def chebyshev_tn(n, x, p):
    if n == 0:
        return 1 % p
    M = [[(2 * x) % p, (-1) % p], [1, 0]]
    power = mat_pow(M, n - 1, p)
    return (power[0][0] * x + power[0][1] * 1) % p

base_val = 0x1337C0DE
frequency_key = 10**25

secret = chebyshev_tn(frequency_key, base_val, p)

flag_enc = Path("flag.enc").read_bytes()
flag = bytes([a ^ b for a, b in zip(flag_enc, long_to_bytes(secret))])

print(flag.decode())
