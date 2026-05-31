from Crypto.Util.number import getPrime, bytes_to_long
import random

FLAG = b"RMCTF{fake_testing_flag}"


def pad(msg):
    prefix = random.randint(2, 2**16)
    return prefix * (2 ** (8 * len(msg))) + bytes_to_long(msg)


def generate_params():
    e = 3
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    return n, e


def main():
    n, e = generate_params()
    m = bytes_to_long(FLAG)

    a = random.randint(2, 100)
    b = random.randint(1, 2**32)
    c = random.randint(2, 100)
    d = random.randint(1, 2**32)

    m1 = (a * m + b) % n
    m2 = (c * m + d) % n

    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)

    print(f"n = {n}")
    print(f"e = {e}")
    print(f"c1 = {c1}")
    print(f"c2 = {c2}")
    print(f"# m1 = {a}*m + {b}")
    print(f"# m2 = {c}*m + {d}")


if __name__ == "__main__":
    main()
