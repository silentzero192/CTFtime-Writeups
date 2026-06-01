#!/usr/bin/env python3

import sys

sys.set_int_max_str_digits(0)

import gmpy2
from Crypto.Util.number import long_to_bytes, inverse

# --------------------------------------------------
# Load N, e, ct from data.txt
# --------------------------------------------------
with open("data.txt") as f:
    exec(f.read())

# --------------------------------------------------
# Rational approximation of e / N^4
# These values come from continued fractions
# --------------------------------------------------
a = 985513
b = 2417906

# --------------------------------------------------
# Estimate p^4 + q^4
#
# Using the relation derived from the challenge,
# we compute an approximation of:
#
#     X = p^4 + q^4
# --------------------------------------------------
R = a * N**4 - b * e
X_approx = R // a

# --------------------------------------------------
# Solve quadratic equation
#
# Roots of:
#     t^2 - X*t + N^4 = 0
#
# correspond to:
#     t = p^4 and q^4
# --------------------------------------------------
disc = X_approx**2 - 4 * N**4
sqrt_disc = gmpy2.isqrt(disc)

P4_approx = (X_approx + sqrt_disc) // 2

# --------------------------------------------------
# Take the fourth root to estimate p
# --------------------------------------------------
p_approx, _ = gmpy2.iroot(P4_approx, 4)

print("[*] Searching for p near approximation...")

# --------------------------------------------------
# Small local search around the approximation
# --------------------------------------------------
p = 0
for offset in range(-1000, 1000):
    candidate = p_approx + offset
    if candidate > 0 and N % candidate == 0:
        p = candidate
        print(f"[+] Found p! Offset = {offset}")
        break

# --------------------------------------------------
# Standard RSA decryption
# --------------------------------------------------
if p != 0:

    q = N // p

    phi = (p - 1) * (q - 1)

    d = inverse(e, phi)

    m = pow(ct, d, N)

    print("\nFlag:")
    print(long_to_bytes(m).decode())

else:
    print("[-] Failed to find p in search range")
