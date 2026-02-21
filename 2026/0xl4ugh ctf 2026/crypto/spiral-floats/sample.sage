#!/usr/bin/env sage
from Crypto.Util.number import bytes_to_long, long_to_bytes
from sage.all import RealField, sqrt, round

def inverse_step(x_next, r, phi):
    # x_next, r, phi are in RealField
    A = x_next - (1 - r) * phi
    disc = r**2 * (A**2 + 1 - 2*r)
    if disc < 0:
        return None
    sqrt_disc = r * sqrt(A**2 + 1 - 2*r)  # note: this is r * sqrt(...), not sqrt(disc)
    denom = 1 - 2*r
    # Two candidates
    u1 = (A*(1-r) + sqrt_disc) / denom
    u2 = (A*(1-r) - sqrt_disc) / denom
    # Check which one is correct by forward step (approximately)
    for u in [u1, u2]:
        if abs(r*sqrt(u**2+1) + (1-r)*(u+phi) - x_next) < 1e-30:
            return u
    return None

def inverse_spiral(y, phi, iterations=81):
    x = y
    for i in reversed(range(iterations)):
        r = i / iterations
        x = inverse_step(x, r, phi)
        if x is None:
            return None
    return x

def main():
    masked = "?7086013?3756162?51694057?5285516?54803756?9202316?39221780?4895755?50591029"
    n = len(masked)  # 76
    k = 9  # number of '?'
    # Positions of '?'
    unknown_positions = [0,8,16,25,33,42,50,59,67]
    
    # Known digits: build a list with None for unknown
    digits = list(masked)
    for i in range(n):
        if digits[i] == '?':
            digits[i] = None
        else:
            digits[i] = int(digits[i])
    
    # We assume first unknown digit is 6 (position 0)
    digits[0] = 6
    
    # Now unknown positions except 0: [8,16,25,33,42,50,59,67]
    # We'll iterate over 10^8 possibilities
    unknown_indices = [8,16,25,33,42,50,59,67]
    
    # Precompute known part of flag integer
    # flag = bytes_to_long(b'0xL4ugh{?????????????????????}')
    # We know first 8 bytes and last byte
    known_prefix = b'0xL4ugh{'
    known_suffix = b'}'
    # Compute K' = sum_{i=0}^{7} byte_i * 256^(31-i) + 125 * 256^0
    K = 0
    for i, b in enumerate(known_prefix):
        K += b * (256**(31-i))
    K += ord(known_suffix)  # 125
    print("K =", K)
    
    # Expected high byte: 48 (most significant byte)
    # Expected low byte: 125
    
    # Precision
    prec = 300
    R = RealField(prec)
    phi = R((1+sqrt(5))/2)
    
    # Decimal point position: after 2 digits
    dp = 2
    
    count = 0
    # Iterate over 8 unknown digits
    for vals in cartesian_product([range(10) for _ in range(8)]):
        # Assign digits
        for idx, val in zip(unknown_indices, vals):
            digits[idx] = val
        # Build digit string
        digit_str = ''.join(str(d) for d in digits)
        # Insert decimal point after dp digits
        y_str = digit_str[:dp] + '.' + digit_str[dp:]
        y = R(y_str)
        # Invert spiral
        x = inverse_spiral(y, phi)
        if x is None or x <= 0 or x >= 1:
            continue
        # Compute flag integer
        flen = 77
        flag_int = round(x * R(10)**flen)
        flag_int = Integer(flag_int)
        # Check low byte
        if flag_int % 256 != 125:
            continue
        # Check high byte
        high_byte = (flag_int >> (31*8)) & 0xFF
        if high_byte != 48:
            continue
        # Convert to bytes
        flag_bytes = long_to_bytes(flag_int)
        if len(flag_bytes) != 32:
            # Maybe adjust length
            continue
        # Check prefix and suffix
        if not (flag_bytes.startswith(known_prefix) and flag_bytes.endswith(known_suffix)):
            continue
        # Check all bytes printable
        if all(32 <= b <= 126 for b in flag_bytes):
            print("Found flag:", flag_bytes)
            return
        count += 1
        if count % 1000000 == 0:
            print("Processed", count)
    
if __name__ == "__main__":
    main()