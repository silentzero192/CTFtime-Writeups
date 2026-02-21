#!/usr/bin/env sage

# Load the polynomial
R.<x> = QQ[]

with open("output.raw", "rb") as f:
    poly = loads(f.read())

# Find the flag points by evaluating at negative integers until we get a non-integer or out of range
flag_points = []
i = 1
while True:
    x_val = -i
    y_val = poly(x_val)
    if y_val in ZZ and 0 <= y_val <= 255:
        flag_points.append((x_val, y_val))
        i += 1
    else:
        break

L = len(flag_points)
print(f"Flag length: {L}")

# Compute the mapping from i to flag index
inv19 = inverse_mod(19, L)
a = (63 * inv19) % L
b = (a * 14 - 40) % L

flag_chars = [0]*L
for x_val, y_val in flag_points:
    i = -x_val - 1  # i from 0 to L-1
    k = (a*i + b) % L
    flag_chars[k] = chr(y_val)

flag = ''.join(flag_chars)
print(flag)