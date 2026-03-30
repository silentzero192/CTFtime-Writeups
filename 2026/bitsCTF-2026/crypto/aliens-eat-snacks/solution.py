#!/usr/bin/env python3
import sys
from tqdm import tqdm

# ---------- GF(2^8) arithmetic ----------
IRREDUCIBLE_POLY = 0x11B


def gf_mult(a, b):
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= IRREDUCIBLE_POLY & 0xFF
        b >>= 1
    return res


def gf_pow(base, exp):
    if exp == 0:
        return 1
    res = 1
    while exp:
        if exp & 1:
            res = gf_mult(res, base)
        base = gf_mult(base, base)
        exp >>= 1
    return res


# ---------- S-box and multiplication tables ----------
SBOX = [gf_pow(x, 23) ^ 0x63 for x in range(256)]
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# Precompute multiplication by constants used in MixColumns
mult2 = [gf_mult(i, 0x02) for i in range(256)]
mult3 = [gf_mult(i, 0x03) for i in range(256)]
# For inverse MixColumns
mult9 = [gf_mult(i, 0x09) for i in range(256)]
mult11 = [gf_mult(i, 0x0B) for i in range(256)]
mult13 = [gf_mult(i, 0x0D) for i in range(256)]
mult14 = [gf_mult(i, 0x0E) for i in range(256)]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# ---------- Key expansion ----------
def expand_key(key):
    # key: bytes of length 16
    words = [list(key[4 * i : 4 * i + 4]) for i in range(4)]
    for i in range(4, 20):  # 4 rounds → 5 round keys = 20 words
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[(i // 4) - 1]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(5):
        rk = bytearray()
        for i in range(4):
            rk.extend(words[r * 4 + i])
        round_keys.append(bytes(rk))
    return round_keys


# ---------- State conversion ----------
def bytes_to_state(data):
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]
    return state


def state_to_bytes(state):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * c + r] = state[r][c]
    return bytes(out)


# ---------- Encryption (4 rounds) ----------
def encrypt_block(round_keys, pt):
    s = bytes_to_state(pt)

    # Round 0: AddRoundKey
    rk = round_keys[0]
    for c in range(4):
        for r in range(4):
            s[r][c] ^= rk[r + 4 * c]

    # Rounds 1,2,3 (with MixColumns)
    for rnd in range(1, 4):
        # SubBytes
        for c in range(4):
            for r in range(4):
                s[r][c] = SBOX[s[r][c]]

        # ShiftRows
        new = [[0] * 4 for _ in range(4)]
        for r in range(4):
            for c in range(4):
                new[r][c] = s[r][(c + r) % 4]
        s = new

        # MixColumns
        new = [[0] * 4 for _ in range(4)]
        for c in range(4):
            a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
            new[0][c] = mult2[a0] ^ mult3[a1] ^ a2 ^ a3
            new[1][c] = a0 ^ mult2[a1] ^ mult3[a2] ^ a3
            new[2][c] = a0 ^ a1 ^ mult2[a2] ^ mult3[a3]
            new[3][c] = mult3[a0] ^ a1 ^ a2 ^ mult2[a3]
        s = new

        # AddRoundKey
        rk = round_keys[rnd]
        for c in range(4):
            for r in range(4):
                s[r][c] ^= rk[r + 4 * c]

    # Final round (no MixColumns)
    for c in range(4):
        for r in range(4):
            s[r][c] = SBOX[s[r][c]]

    new = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            new[r][c] = s[r][(c + r) % 4]
    s = new

    rk = round_keys[4]
    for c in range(4):
        for r in range(4):
            s[r][c] ^= rk[r + 4 * c]

    return state_to_bytes(s)


# ---------- Decryption (4 rounds) ----------
def decrypt_block(round_keys, ct):
    s = bytes_to_state(ct)

    # Final round inverse
    rk = round_keys[4]
    for c in range(4):
        for r in range(4):
            s[r][c] ^= rk[r + 4 * c]

    # InvShiftRows
    new = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            new[r][c] = s[r][(c - r) % 4]
    s = new

    # InvSubBytes
    for c in range(4):
        for r in range(4):
            s[r][c] = INV_SBOX[s[r][c]]

    # Rounds 3,2,1 (with InvMixColumns)
    for rnd in range(3, 0, -1):
        # AddRoundKey
        rk = round_keys[rnd]
        for c in range(4):
            for r in range(4):
                s[r][c] ^= rk[r + 4 * c]

        # InvMixColumns
        new = [[0] * 4 for _ in range(4)]
        for c in range(4):
            a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
            new[0][c] = mult14[a0] ^ mult11[a1] ^ mult13[a2] ^ mult9[a3]
            new[1][c] = mult9[a0] ^ mult14[a1] ^ mult11[a2] ^ mult13[a3]
            new[2][c] = mult13[a0] ^ mult9[a1] ^ mult14[a2] ^ mult11[a3]
            new[3][c] = mult11[a0] ^ mult13[a1] ^ mult9[a2] ^ mult14[a3]
        s = new

        # InvShiftRows
        new = [[0] * 4 for _ in range(4)]
        for r in range(4):
            for c in range(4):
                new[r][c] = s[r][(c - r) % 4]
        s = new

        # InvSubBytes
        for c in range(4):
            for r in range(4):
                s[r][c] = INV_SBOX[s[r][c]]

    # Initial AddRoundKey
    rk = round_keys[0]
    for c in range(4):
        for r in range(4):
            s[r][c] ^= rk[r + 4 * c]

    return state_to_bytes(s)


# ---------- Parse output.txt ----------
def read_data(filename):
    with open(filename, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    key_hint = None
    enc_flag = None
    samples = []
    for line in lines:
        if line.startswith("key_hint:"):
            key_hint = line.split(": ")[1]
        elif line.startswith("encrypted_flag:"):
            enc_flag = line.split(": ")[1]
        elif line.startswith("num_samples:"):
            continue
        elif "," in line:
            pt, ct = line.split(",")
            samples.append((pt.strip(), ct.strip()))
    return key_hint, enc_flag, samples


def main():
    key_hint, enc_flag, samples = read_data("output.txt")
    if not key_hint or not enc_flag or len(samples) < 2:
        print("Failed to parse input")
        return

    hint = bytes.fromhex(key_hint)  # 13 bytes
    first_pt = bytes.fromhex(samples[0][0])
    first_ct = bytes.fromhex(samples[0][1])
    second_pt = bytes.fromhex(samples[1][0])
    second_ct = bytes.fromhex(samples[1][1])

    # Try suffix (unknown at the end)
    print("Trying suffix (unknown last 3 bytes)...")
    for i in tqdm(range(0x1000000)):
        suffix = i.to_bytes(3, "big")
        key = hint + suffix
        rks = expand_key(key)
        if encrypt_block(rks, first_pt) == first_ct:
            # verify with second sample
            if encrypt_block(expand_key(key), second_pt) == second_ct:
                print(f"\nFound key: {key.hex()}")
                break
    else:
        # Try prefix (unknown at the beginning)
        print("Suffix not found, trying prefix...")
        for i in tqdm(range(0x1000000)):
            prefix = i.to_bytes(3, "big")
            key = prefix + hint
            rks = expand_key(key)
            if encrypt_block(rks, first_pt) == first_ct:
                if encrypt_block(expand_key(key), second_pt) == second_ct:
                    print(f"\nFound key: {key.hex()}")
                    break
        else:
            print("Key not found with suffix or prefix.")
            return

    # Decrypt the flag
    flag_bytes = bytes.fromhex(enc_flag)
    blocks = [flag_bytes[i : i + 16] for i in range(0, len(flag_bytes), 16)]
    plain = b""
    rks = expand_key(key)  # round keys for the found key
    for blk in blocks:
        plain += decrypt_block(rks, blk)
    print("Flag:", plain.decode("utf-8", errors="ignore"))


if __name__ == "__main__":
    main()

# BITSCTF{7h3_qu1ck_br0wn_f0x_jump5_0v3r_7h3_l4zy_d0g}
