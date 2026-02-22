import itertools
from Crypto.Util.number import long_to_bytes
import sympy

n = 147411106158287041622784593501613775873740698182074300197321802109276152016347880921444863007
e = 3
c = 114267757154492856513993877195962986022489770009120200367811440852965239059854157313462399351

fast_factors = [
    8532679,
    9613003,
    9742027,
    10660669,
    11451571,
    11862439,
    11908471,
    13164721,
    13856221,
    14596051,
    15607783,
    15840751,
    16249801,
]

roots_per_p = []
for p in fast_factors:
    roots = sympy.ntheory.residue_ntheory.nthroot_mod(c, 3, p, all_roots=True)
    if not roots:
        print(f"No roots for p={p}")
        exit()
    roots_per_p.append(roots)

# Precompute CRT constants
C = []
for p in fast_factors:
    N_p = n // p
    inv = pow(N_p, -1, p)
    C.append(N_p * inv)

print(f"Computed roots for all primes. Checking combinations...")

# To speed up, we don't need to generate all 1.5 million strings.
# The message starts with b"BCCTF{", so its value should be in a certain range.
# But just generating and checking the high bits or just bytes is fast enough.

target_prefix = b"BCCTF{"

# But wait, we can also check the combinations progressively, or just run them.
count = 0
for combination in itertools.product(*roots_per_p):
    count += 1
    if count % 100000 == 0:
        print(f"Processed {count} combinations")

    m = sum(r * c_m for r, c_m in zip(combination, C)) % n
    m_bytes = long_to_bytes(m)
    if b"BCCTF{" in m_bytes:
        print(f"\nFOUND FLAG: {m_bytes}\n")
        break
