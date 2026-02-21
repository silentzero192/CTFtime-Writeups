import math

n = 147170819334030469053514652921356515888015711942553338463409772437981228515273287953989706666936875524451626901247038180594875568558137526484665015890594045767912340169965961750130156341999306808017498374501001042628249176543370525803456692022546235595791111819909503496986338431136130272043196908119165239297
c = 77151713996168344370880352082934801122524956107256445231326053049976568087412199358725058612262271922128984783428798480191211811217854076875727477848490840660333035334309193217618178091153472265093622822195960145852562781183839474868269109313543427082414220136748700364027714272845969723750108397300867408537
e = 1234567891


def man(n):
    B = bin(n)[2:]
    M = ""
    for b in B:
        if b == "0":
            M += "01"
        else:
            M += "11"
    return int(M, 2)


# Constants
nbit = 256
K = 2**nbit
M = 2**128

# C = (4^256 - 1)/3
C = (4**256 - 1) // 3

# Step 1: Use modular arithmetic to get information about x
# We have: n = p * q = [K*x + (K-1)] * man(x)
# Let's work modulo K:
# n ≡ (K-1) * man(x) mod K
# n ≡ -man(x) mod K  (since K-1 ≡ -1 mod K)
# So: man(x) ≡ -n mod K

man_x_mod_K = (-n) % K

# Now, man(x) = sum_{i=0}^{255} (2*b_i + 1) * 4^i
# Let S = sum_{i=0}^{255} b_i * 4^i
# Then man(x) = C + 2*S, where C = (4^256 - 1)/3

# So: C + 2*S ≡ man_x_mod_K (mod K)
# 2*S ≡ man_x_mod_K - C (mod K)

rhs = (man_x_mod_K - C) % K

# Since 2 has inverse modulo K? K is power of 2, so 2 doesn't have inverse mod K
# But we can divide by 2 if rhs is even
if rhs % 2 != 0:
    print("Error: rhs is not even")
    exit()

S_mod_halfK = rhs // 2

# S_mod_halfK gives us S mod 2^255
# S = sum_{i=0}^{255} b_i * 4^i
# For i >= 128, 4^i ≡ 0 mod 2^255? 4^128 = 2^256, which is 0 mod 2^255
# So we only get information about bits 0-127

# Extract bits from S_mod_halfK
# S_mod_halfK = sum_{i=0}^{127} b_i * 4^i mod 2^255
# Since 4^i = 2^(2i), we can extract b_i from positions 2i

bits_low = [0] * 128
for i in range(128):
    # Check if bit 2i is set in S_mod_halfK
    if (S_mod_halfK >> (2 * i)) & 1:
        bits_low[i] = 1

# Reconstruct x_low (lower 128 bits of x)
x_low = 0
for i in range(128):
    if bits_low[i]:
        x_low += 1 << i

# Reconstruct S_low
S_low = 0
for i in range(128):
    if bits_low[i]:
        S_low += 4**i

# Now we need to find x_high (upper 128 bits)
# Let x = x_low + M * x_high, where M = 2^128
# Let S = S_low + 4^128 * S_high
# Note: 4^128 = 2^256 = K

# We have: n = [K*x + (K-1)] * (C + 2*S)
# = [K*(x_low + M*x_high) + (K-1)] * (C + 2*(S_low + K*S_high))
# = [K*x_low + K*M*x_high + K-1] * (C + 2*S_low + 2*K*S_high)

# Let q0 = C + 2*S_low
# Then: n = [K*x_low + K-1 + K*M*x_high] * (q0 + 2*K*S_high)

# Expand:
# n = (K*x_low + K-1)*q0 + (K*x_low + K-1)*2*K*S_high + K*M*x_high*q0 + K*M*x_high*2*K*S_high

# Rearrange terms by powers of K:
# n = A0 + A1*K + A2*K^2, where:
# A0 = (K-1)*q0
# A1 = x_low*q0 + 2*(K-1)*S_high + M*x_high*q0
# A2 = 2*M*x_high*S_high

# But note: K = 2^256, so K^2 is 2^512
# n is about 1024 bits, so all terms matter

# Better approach: Solve for x_high by brute force of upper bits
# Since we have 128 unknown bits, brute force is impossible
# But we can use the fact that x_high appears in both S_high and x_high terms

# Alternative: We know the relationship between x_high and S_high:
# S_high = sum_{i=0}^{127} b_{i+128} * 4^i
# where b_{i+128} are the bits of x_high

# So we can try to solve bit by bit
# We already have an equation for n

# Let's try a simpler approach: Binary search for x
print("Starting binary search for x...")


def compute_n_from_x(x):
    """Compute n from x using the key generation formula"""
    K = 2**256
    C = (4**256 - 1) // 3

    # Compute man(x)
    man_x = man(x)

    # Compute p = K*x + (K-1)
    p_val = K * x + (K - 1)

    # Compute q = man(x)
    q_val = man_x

    return p_val * q_val


# Binary search for x
# x is 256-bit, so between 2^255 and 2^256-1
low = 2**255
high = 2**256 - 1

found = False
x_found = None

# Since binary search of 2^256 space is too big, let's use the fact
# that we know the lower 128 bits
# x = x_low + M * x_high, where M = 2^128
# x_high is between 0 and 2^128-1

print(f"x_low: {x_low}")
print("Starting binary search for x_high...")

low_high = 0
high_high = 2**128 - 1

for i in range(128):
    mid_high = (low_high + high_high) // 2
    x_test = x_low + M * mid_high
    n_test = compute_n_from_x(x_test)

    if n_test == n:
        x_found = x_test
        found = True
        print(f"Found x at iteration {i}")
        break
    elif n_test < n:
        low_high = mid_high + 1
    else:
        high_high = mid_high - 1

if not found:
    # Try the neighborhood
    print("Exact match not found in binary search, trying nearby values...")
    for offset in range(-1000, 1000):
        x_test = x_low + M * mid_high + offset
        if x_test < 2**255 or x_test >= 2**256:
            continue
        n_test = compute_n_from_x(x_test)
        if n_test == n:
            x_found = x_test
            found = True
            print(f"Found x with offset {offset}")
            break

if not found:
    print("Could not find x")
    exit()

print(f"Found x: {x_found}")

# Verify
K = 2**256
p = K * x_found + (K - 1)
q = man(x_found)

print(f"p: {p}")
print(f"q: {q}")
print(f"n computed: {p * q}")
print(f"n given: {n}")

if p * q == n:
    print("Factorization successful!")

    # Decrypt
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)

    # Convert to flag
    try:
        flag = bytes.fromhex(hex(m)[2:])
        print(f"Flag: {flag}")
    except:
        flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
        print(f"Flag: {flag}")
else:
    print("Factorization failed")
