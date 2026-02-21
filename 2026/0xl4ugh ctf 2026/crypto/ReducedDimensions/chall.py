from Crypto.Util.number import bytes_to_long, getStrongPrime, long_to_bytes


def get_quaternion_matrix(a0, a1, a2, a3, n):
    return [
        [a0 % n, (-a1) % n, (-a2) % n, (-a3) % n],
        [a1 % n, a0 % n, (-a3) % n, a2 % n],
        [a2 % n, a3 % n, a0 % n, (-a1) % n],
        [a3 % n, (-a2) % n, a1 % n, a0 % n],
    ]


def matrix_mult(A, B, n):
    C = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            for k in range(4):
                C[i][j] = (C[i][j] + A[i][k] * B[k][j]) % n
    return C


def matrix_pow(A, e, n):
    res = [[0] * 4 for _ in range(4)]
    for i in range(4):
        res[i][i] = 1
    while e > 0:
        if e % 2 == 1:
            res = matrix_mult(res, A, n)
        A = matrix_mult(A, A, n)
        e //= 2
    return res


e = 0x10001
p = getStrongPrime(1024)
q = getStrongPrime(1024)
n = p * q

flag = b"REDACTED"
m = bytes_to_long(flag)
a0 = m
a1 = m + 3 * p + 7 * q
a2 = m + 11 * p + 13 * q
a3 = m + 17 * p + 19 * q

A = get_quaternion_matrix(a0, a1, a2, a3, n)

encrypted_matrix = matrix_pow(A, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"ciphertext = {encrypted_matrix[0]}")
