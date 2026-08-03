#!/usr/bin/env python3
"""
solve.py -- VuwCTF 2026 "reversing" challenge: cc
=================================================

The challenge ships a single file, ``cc.cpython-314.pyc``, a Python 3.14
byte-compiled module whose source was ``coro_anom.py``.  At runtime it:

    flag = input("Flag: ")
    assert len(flag) == 32
    (k0, k1) = flag[:16], flag[16:]
    v = AES256_CBC_encrypt(key=K, iv=0x00...00, plaintext=flag)
    if v == TARGET: print("Correct") else print("Incorrect")

* K (the AES-256 key) and the S-box are fixed constants, derived
  deterministically at import time by gp() / gc().
* TARGET (the 32-byte ciphertext to match) is a big-integer literal in the
  final comparison:  TARGET = 0xf6504e32...16f4165d, serialised with
  Python 3.14's new 1-arg int.to_bytes(32) (big-endian default).

So the flag is simply:  AES256_CBC_decrypt(key=K, iv=0, ct=TARGET).

This solver is fully self-contained (stdlib only; no external crypto
libraries).  It:

  1. loads the pyc with ``marshal``,
  2. extracts TARGET from the bytecode constants,
  3. recovers K and the S-box by observing a single run of the module
     (``sys.settrace`` on the block-cipher entry point ``gl``),
  4. decrypts TARGET with a from-scratch AES-256 (CBC, IV=0),
  5. verifies the result by re-encrypting and by running the real module.

Usage:
    python3.14 solve.py
"""

import marshal
import sys

HERE = __file__.rsplit("/", 1)[0] if "/" in __file__ else "."
PYC = HERE + "/cc.cpython-314.pyc"


# --------------------------------------------------------------------------
# 1. Load the compiled module
# --------------------------------------------------------------------------
with open(PYC, "rb") as f:
    data = f.read()

# pyc header is 16 bytes on Python 3.7+; everything after is one marshal blob
code = marshal.loads(data[16:])

print(f"[*] loaded {PYC} ({len(data)} bytes, magic {data[:4].hex()})")


# --------------------------------------------------------------------------
# 2. Extract TARGET from the bytecode constants
# --------------------------------------------------------------------------
# The final check in the module is roughly:
#     all(w == x for (w, x) in zip(v, <bigint>.to_bytes(32)))
# The bigint is the only 256-bit literal in the whole program.
def find_target(obj):
    found = []
    stack = [obj]
    while stack:
        o = stack.pop()
        if hasattr(o, "co_consts"):
            for c in o.co_consts:
                if isinstance(c, int) and (c.bit_length() + 7) // 8 == 32:
                    found.append(c)
                stack.append(c)
    assert found, "target integer not found"
    assert len(set(found)) == 1, "multiple candidate targets: %r" % found
    return found[0].to_bytes(32)  # 3.14 int.to_bytes defaults to 'big'


target = find_target(code)
print(f"[*] target ciphertext : {target.hex()}")


# --------------------------------------------------------------------------
# 3. Recover the AES parameters (key + S-box) from a single run
# --------------------------------------------------------------------------
# gl(a, b, c) is the AES block-cipher entry point:
#     a = key words (8 x 32-bit big-endian = 32-byte AES-256 key)
#     b = 16-byte plaintext block
#     c = S-box (256 entries)
# Key and S-box are independent of the flag, so running the module with any
# 32-byte input and tapping gl once is enough to recover them.
captured = {}


def _trace(frame, event, arg):
    # capture only the first call to gl (the first CBC block)
    if event == "call" and frame.f_code.co_name == "gl" and "key_words" not in captured:
        captured["key_words"] = list(frame.f_locals["a"])
        captured["sbox"] = list(frame.f_locals["c"])
        captured["first_block"] = list(frame.f_locals["b"])
    return None


sys.settrace(_trace)
g = {
    "__name__": "__main__",
    "__builtins__": __import__("builtins"),
    "input": lambda prompt="": "A" * 32,
    "print": lambda *a, **k: None,
}
exec(code, g)                     # this also runs the final check once
sys.settrace(None)

key_words = captured["key_words"]
sbox = captured["sbox"]

# Sanity checks: S-box must be the standard AES S-box, and CBC(iv=0) must be
# in effect (first block is the raw first 16 input bytes).
std_sbox_head = bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                       0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])
assert bytes(sbox[:16]) == std_sbox_head, "unexpected S-box"
assert captured["first_block"] == [ord("A")] * 16, "unexpected CBC mode"

key = b"".join(w.to_bytes(4, "big") for w in key_words)
print(f"[*] recovered AES-256 key : {key.hex()}")
print("[*] S-box is the standard AES S-box")

# The key words as constants (stable across runs) -- handy to hard-code.
print("[*] key words            :", key_words)


# --------------------------------------------------------------------------
# 4. From-scratch AES-256 (encrypt + decrypt), pure stdlib
# --------------------------------------------------------------------------
SBOX = sbox  # already extracted and verified == standard AES S-box
INV_SBOX = [SBOX.index(i) for i in range(256)]
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _sub_word(w):
    return ((SBOX[(w >> 24) & 0xFF] << 24) | (SBOX[(w >> 16) & 0xFF] << 16) |
            (SBOX[(w >> 8) & 0xFF] << 8) | SBOX[w & 0xFF])


def _rot_word(w):
    return ((w << 8) | (w >> 24)) & 0xFFFFFFFF


def expand_key(words):
    """AES-256 key schedule: 8 x 32-bit words -> 60 words."""
    w = list(words)
    for i in range(8, 60):
        t = w[i - 1]
        if i % 8 == 0:
            t = _sub_word(_rot_word(t)) ^ (RCON[i // 8 - 1] << 24)
        elif i % 8 == 4:
            t = _sub_word(t)
        w.append(w[i - 8] ^ t)
    return w


def round_keys(words):
    w = expand_key(words)
    return [[w[4 * r + j] for j in range(4)] for r in range(15)]


def _add_rk(state, rk):
    out = []
    for i in range(16):
        out.append(state[i] ^ ((rk[i // 4] >> (24 - 8 * (i % 4))) & 0xFF))
    return out


def _sub_bytes(state):
    return [SBOX[b] for b in state]


def _inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


def _shift_rows(state):
    # state[r + 4*c] = row r, column c; row r shifts left by r
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r + 4 * ((c + r) % 4)]
    return out


def _inv_shift_rows(state):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r + 4 * ((c - r) % 4)]
    return out


def _xtime(b):
    return ((b << 1) ^ (0x1B if b & 0x80 else 0)) & 0xFF


def _gmul(b, e):  # GF(2^8) multiply by e
    r = 0
    for _ in range(8):
        if e & 1:
            r ^= b
        b = _xtime(b)
        e >>= 1
    return r


def _mix_columns(state):
    out = list(state)
    for c in range(4):
        a = state[4 * c:4 * c + 4]
        out[4 * c + 0] = _xtime(a[0]) ^ _xtime(a[1]) ^ a[1] ^ a[2] ^ a[3]
        out[4 * c + 1] = a[0] ^ _xtime(a[1]) ^ _xtime(a[2]) ^ a[2] ^ a[3]
        out[4 * c + 2] = a[0] ^ a[1] ^ _xtime(a[2]) ^ _xtime(a[3]) ^ a[3]
        out[4 * c + 3] = _xtime(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ _xtime(a[3])
    return out


def _inv_mix_columns(state):
    out = list(state)
    for c in range(4):
        a = state[4 * c:4 * c + 4]
        out[4 * c + 0] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
        out[4 * c + 1] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
        out[4 * c + 2] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
        out[4 * c + 3] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)
    return out


def aes_encrypt_block(block, words):
    rks = round_keys(words)
    state = _add_rk(list(block), rks[0])
    for r in range(1, 14):
        state = _mix_columns(_shift_rows(_sub_bytes(state)))
        state = _add_rk(state, rks[r])
    state = _shift_rows(_sub_bytes(state))
    state = _add_rk(state, rks[14])
    return state


def aes_decrypt_block(block, words):
    rks = round_keys(words)
    state = _add_rk(list(block), rks[14])
    for r in range(13, 0, -1):
        state = _inv_shift_rows(_inv_sub_bytes(state))
        state = _add_rk(state, rks[r])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(_inv_sub_bytes(state))
    state = _add_rk(state, rks[0])
    return state


# --------------------------------------------------------------------------
# 5. Decrypt TARGET (AES-256-CBC, IV = 0)
# --------------------------------------------------------------------------
def cbc_decrypt(ct, words):
    pt = bytes(aes_decrypt_block(list(ct[0:16]), words))
    pt += bytes(a ^ b for a, b in
                zip(aes_decrypt_block(list(ct[16:32]), words), ct[0:16]))
    return pt


def cbc_encrypt(pt, words):
    ct0 = bytes(aes_encrypt_block(list(pt[0:16]), words))
    ct1 = bytes(aes_encrypt_block(list(a ^ b for a, b in zip(pt[16:32], ct0)),
                                  words))
    return ct0 + ct1


flag = cbc_decrypt(target, key_words)
print(f"[+] flag               : {flag.decode('ascii', 'replace')}")

# --------------------------------------------------------------------------
# 6. Verify
# --------------------------------------------------------------------------
assert cbc_encrypt(flag, key_words) == target, "re-encryption mismatch"
print("[*] re-encryption matches TARGET")

out = []
g2 = {
    "__name__": "__main__",
    "__builtins__": __import__("builtins"),
    "input": lambda prompt="": flag.decode("ascii"),
    "print": lambda *a, **k: out.append(a),
}
exec(code, g2)
assert out and out[0][0] == "Correct", "challenge rejected the flag: %r" % out
print("[*] challenge output   :", out[0][0])
