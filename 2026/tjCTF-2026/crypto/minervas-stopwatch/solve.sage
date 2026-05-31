import csv

# Parse trace data
traces = []
with open('trace.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        traces.append({
            'id': int(row['id']),
            'msg_hex': row['msg_hex'],
            'h': int(row['h'], 16),
            'r': int(row['r'], 16),
            's': int(row['s'], 16),
            'elapsed_ns': int(row['elapsed_ns'])
        })

# Sort by timing
traces_sorted = sorted(traces, key=lambda t: t['elapsed_ns'])

print(f"Total signatures: {len(traces)}")
print(f"Fastest: {traces_sorted[0]['elapsed_ns']} ns")
print(f"Slowest: {traces_sorted[-1]['elapsed_ns']} ns")

# Print timing distribution
timings = [t['elapsed_ns'] for t in traces_sorted]
print(f"\nTiming range: {min(timings)} - {max(timings)}")
print(f"Mean: {sum(timings)/len(timings):.0f}")
print(f"Median: {timings[len(timings)//2]}")

# Find significant gaps/clusters
print("\nTop 20 fastest timings:")
for i in range(20):
    print(f"  id={traces_sorted[i]['id']:3d}  elapsed={traces_sorted[i]['elapsed_ns']}")

print("\nBottom 20 slowest timings:")
for i in range(20):
    t = traces_sorted[-(i+1)]
    print(f"  id={t['id']:3d}  elapsed={t['elapsed_ns']}")

# P-256 parameters
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Public key
Qx = 0xa51b379a175d3a2593d698e47379becb0c1a541357bca5aa8324edf182a7ac44
Qy = 0x00c4b6868e9610c21282b31fb59d988f842fa4179ce9803c84de2501391cc656

F = GF(p)
EC = EllipticCurve(F, [a, b])
G = EC(Gx, Gy)
Q = EC(Qx, Qy)

print(f"\nGenerator order verified: {G * n == 0}")
print(f"Public key valid: {Q * n == 0}")

# The Minerva attack: We know signatures with lower timing had smaller nonces k
# Let's use the fastest t signatures and assume k has some leading zero bits

def solve_with_lattice(traces, num_sigs, k_bits_known):
    """
    Try to recover private key d using HNP lattice attack.
    k_bits_known = number of MSB bits we know (or assume) are zero
    """
    selected = traces[:num_sigs]
    t = num_sigs
    
    as_ = []
    bs_ = []
    for trace in selected:
        h, r, s = trace['h'], trace['r'], trace['s']
        si = inverse_mod(int(s), n)
        ai = (int(h) * si) % n
        bi = (int(r) * si) % n
        as_.append(ai)
        bs_.append(bi)
    
    # Lattice dimension: t + 2
    # We know k_i < 2^(256 - k_bits_known)
    B = 2^(256 - k_bits_known)
    
    # Construct the lattice
    M = matrix(ZZ, t + 2, t + 2)
    
    # Identity * n on diagonal for first t columns
    for i in range(t):
        M[i, i] = n
    
    # Last two columns
    for i in range(t):
        M[t, i] = bs_[i]
        M[t+1, i] = as_[i]
    
    M[t, t] = 1
    M[t+1, t+1] = n  # or B, let's try n
    
    # Actually a better lattice construction:
    # Let's use the standard one from Nguyen-Shparlinski
    
    M2 = matrix(ZZ, t + 2, t + 2)
    for i in range(t):
        M2[i, i] = n
        M2[t, i] = bs_[i]
        M2[t+1, i] = as_[i]
    M2[t, t] = B  # scaling factor = 1
    M2[t+1, t+1] = 1
    
    print(f"Running LLL on {t+2}x{t+2} lattice (k < 2^{256-k_bits_known})...")
    ML = M2.LLL()
    
    for row in ML:
        # Check if last element is 1 or -1 (our scaling)
        if abs(row[t+1]) == 1:
            d_candidate = abs(int(row[t])) % n
            # Verify
            if Q == d_candidate * G:
                return d_candidate
            # Also check negative
            if Q == (-d_candidate % n) * G:
                return (-d_candidate % n)
    
    return None

# Try different parameters
# The Minerva attack: timing correlates with k size
# Fastest signatures should have smallest k values

print("\n=== Trying lattice attack ===")

for num_sigs in [30, 50, 75, 100, 150]:
    for k_bits in [2, 4, 6, 8, 10, 12, 16]:
        d = solve_with_lattice(traces_sorted, num_sigs, k_bits)
        if d is not None:
            print(f"\nFOUND PRIVATE KEY: d = {hex(d)}")
            print(f"num_sigs={num_sigs}, k_bits_known={k_bits}")

# Also try: use a threshold-based approach where we only include signatures
# below a certain timing threshold (e.g., fastest 10%, 20%, etc.)
print("\n=== Trying percentile-based selection ===")

for percentile in [5, 10, 15, 20, 25, 30]:
    cutoff_idx = len(traces_sorted) * percentile // 100
    traces_subset = traces_sorted[:cutoff_idx]
    num_sigs = len(traces_subset)
    
    # These are the fastest, likely have at least some leading zero bits
    # Estimate: the fastest might have ~8+ leading zeros
    for k_bits in [4, 6, 8, 10, 12, 16]:
        d = solve_with_lattice(traces_subset, num_sigs, k_bits)
        if d is not None:
            print(f"\nFOUND PRIVATE KEY: d = {hex(d)}")
            print(f"percentile={percentile}, num_sigs={num_sigs}, k_bits={k_bits}")
