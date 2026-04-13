#!/usr/bin/env python3
from math import gcd


def parse_output(path="output.txt"):
    data = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = int(value.strip())
    return data


def integer_nth_root(value, n):
    if value < 0:
        raise ValueError("negative value")
    if value in (0, 1):
        return value, True
    bit_length = value.bit_length()
    high = 1 << ((bit_length + n - 1) // n + 1)
    low = 0
    while low < high:
        mid = (low + high) // 2
        power = pow(mid, n)
        if power == value:
            return mid, True
        if power < value:
            low = mid + 1
        else:
            high = mid
    root = low - 1
    return root, pow(root, n) == value


def modinv(a, modulo):
    a %= modulo
    g = gcd(a, modulo)
    if g != 1:
        raise ValueError("no inverse for %d mod %d" % (a, modulo))
    return pow(a, -1, modulo)


def poly_normalize(p):
    while p and p[-1] == 0:
        p.pop()
    return p


def poly_add(a, b, n):
    res = []
    for i in range(max(len(a), len(b))):
        ai = a[i] if i < len(a) else 0
        bi = b[i] if i < len(b) else 0
        res.append((ai + bi) % n)
    return poly_normalize(res)


def poly_sub(a, b, n):
    res = []
    for i in range(max(len(a), len(b))):
        ai = a[i] if i < len(a) else 0
        bi = b[i] if i < len(b) else 0
        res.append((ai - bi) % n)
    return poly_normalize(res)


def poly_mul(a, b, n):
    if not a or not b:
        return []
    res = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            res[i + j] = (res[i + j] + ai * bj) % n
    return poly_normalize(res)


def poly_scalar_mul(p, scalar, n):
    return poly_normalize([(coef * scalar) % n for coef in p])


def poly_shift(p, k):
    if not p:
        return []
    return [0] * k + p


def poly_pow(base, exponent, n):
    result = [1]
    acc = base[:]
    while exponent:
        if exponent & 1:
            result = poly_mul(result, acc, n)
        acc = poly_mul(acc, acc, n)
        exponent >>= 1
    return result


def poly_pseudo_remainder(a, b, n):
    a = poly_normalize(a[:])
    b = poly_normalize(b[:])
    if not b:
        raise ValueError("division by zero polynomial")
    degree_b = len(b) - 1
    lc_b = b[-1]
    while a and len(a) - 1 >= degree_b:
        degree_a = len(a) - 1
        coeff = a[-1]
        shift = degree_a - degree_b
        a = poly_scalar_mul(a, lc_b, n)
        term = poly_scalar_mul(b, coeff, n)
        term = poly_shift(term, shift)
        a = poly_sub(a, term, n)
    return poly_normalize(a)


def poly_gcd(a, b, n):
    a = poly_normalize(a[:])
    b = poly_normalize(b[:])
    while b:
        r = poly_pseudo_remainder(a, b, n)
        a, b = b, r
    return poly_normalize(a)


def main():
    data = parse_output()
    n = data["n"]
    e = data["e"]
    points = [(data[f"x{i}"], data[f"y{i}"], data[f"r{i}"]) for i in range(1, 11)]

    xy = []
    for x, y, r_enc in points:
        r, ok = integer_nth_root(r_enc, e)
        if not ok:
            raise SystemExit("failed to recover noise")
        xy.append((x, (y - r) % n))

    poly = [0]
    for i, (xi, yi) in enumerate(xy):
        term = [yi]
        denom = 1
        for j, (xj, _) in enumerate(xy):
            if i == j:
                continue
            term = poly_mul(term, [(-xj) % n, 1], n)
            denom = (denom * ((xi - xj) % n)) % n
        term = poly_scalar_mul(term, modinv(denom, n), n)
        poly = poly_add(poly, term, n)

    poly_f_e = poly_pow(poly, e, n)
    polynomial_g = poly_sub(poly_f_e, [data["c2"]], n)
    polynomial_h = poly_sub([0] * e + [1], [data["c1"]], n)

    gcd_poly = poly_gcd(polynomial_g, polynomial_h, n)
    if len(gcd_poly) != 2:
        raise SystemExit("unexpected gcd degree")

    a = gcd_poly[1]
    b = gcd_poly[0]
    root = (-b * modinv(a, n)) % n
    length = (root.bit_length() + 7) // 8
    flag = root.to_bytes(length, "big")
    print("flag =", flag.decode("utf-8"))


if __name__ == "__main__":
    main()
