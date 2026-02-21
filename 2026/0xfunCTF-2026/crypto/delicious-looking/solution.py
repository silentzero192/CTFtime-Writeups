from sympy.ntheory import discrete_log
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from math import gcd, lcm
from functools import reduce
import hashlib

# ── Data ──────────────────────────────────────────────────────────────────────
samples = [
    dict(g=227293414901,  h=1559214942312, p=3513364021163),
    dict(g=2108076514529, h=1231299005176, p=2627609083643),
    dict(g=1752240335858, h=1138499826278, p=2917520243087),
    dict(g=1564551923739, h=283918762399,  p=2602533803279),
    dict(g=1809320390770, h=700655135118,  p=2431482961679),
    dict(g=1662077312271, h=354214090383,  p=2820691962743),
    dict(g=474213905602,  h=1149389382916, p=3525049671887),
    dict(g=2013522313912, h=2559608094485, p=2679851241659),
]
ct = bytes.fromhex(
    '175a6f682303e313e7cae01f4579702ae6885644d46c15747c39b85e5a1fab66'
    '7d2be070d383268d23a6387a4b3ec791'
)

# ── Step 1: Solve DLP in each small group ────────────────────────────────────
# p is 42-bit safe prime (p = 2q+1, q 41-bit prime)
# g is a primitive root → order = p-1 = 2q
# DLP gives key_int ≡ x_i  (mod p_i - 1)
print("[*] Solving discrete logs (42-bit primes, trivial BSGS)...")
residues, moduli = [], []
for i, s in enumerate(samples):
    g, h, p = s['g'], s['h'], s['p']
    x = discrete_log(p, h, g)
    assert pow(g, x, p) == h, "DLP sanity check failed"
    print(f"  sample #{i+1}: key_int ≡ {x}  (mod {p-1})")
    residues.append(x)
    moduli.append(p - 1)

# ── Step 2: Generalised CRT (moduli share factor 2) ──────────────────────────
def extended_gcd(a, b):
    if b == 0: return a, 1, 0
    g2, x2, y2 = extended_gcd(b, a % b)
    return g2, y2, x2 - (a // b) * y2

def modinv(a, mod):
    _, x, _ = extended_gcd(a % mod, mod)
    return x % mod

def generalised_crt(residues, moduli):
    x, m = residues[0], moduli[0]
    for r, n in zip(residues[1:], moduli[1:]):
        g = gcd(m, n)
        assert (r - x) % g == 0, "Inconsistent system"
        inv = modinv(m // g, n // g)
        x = x + m * (((r - x) // g) * inv % (n // g))
        m = m * n // g
        x %= m
    return x, m

print("\n[*] Running generalised CRT...")
key_val, combined_mod = generalised_crt(residues, moduli)
assert combined_mod == reduce(lcm, moduli), "CRT modulus ≠ LCM sanity check"
print(f"  key_int ≡ key_val  (mod combined_mod)")
print(f"  key_val   = {key_val}  ({key_val.bit_length()} bits)")
print(f"  combined_mod bits = {combined_mod.bit_length()}")

# ── Step 3: AES helpers ──────────────────────────────────────────────────────
def aes_ecb_decrypt(key32, ct):
    cipher = Cipher(algorithms.AES(key32), modes.ECB())
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()

def unpad_pkcs7(data):
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError("bad padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("bad padding")
    return data[:-pad_len]

# ── Step 4: Brute-force over residue class ───────────────────────────────────
# AES-ECB ciphertext = 48 bytes  →  flag = 33..47 bytes (PKCS7)
# key_val is 324 bits; minimum key_len to hold it = 41 bytes.
# For key_len = 43: ~1 million candidates, trivially feasible.
print("\n[*] Searching residue class for correct key (key_len=43, ~1M candidates)...")
key_len = 43
max_val = 1 << (key_len * 8)
c = key_val
cnt = 0
flag = None

while c < max_val:
    kb = c.to_bytes(key_len, 'big')
    digest = hashlib.sha256(kb).digest()
    raw = aes_ecb_decrypt(digest, ct)
    try:
        pt = unpad_pkcs7(raw)
        if all(32 <= b < 127 for b in pt):
            flag = pt.decode()
            print(f"\n[+] FLAG: {flag}")
            break
    except Exception:
        pass
    c += combined_mod
    cnt += 1

if flag is None:
    print("Not found in key_len=43, try expanding the search.")
print(f"\n[*] Checked {cnt:,} candidates.")
