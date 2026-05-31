#!/usr/bin/env python3
"""
Nujum Ledger - Solution Script
Challenge: 0xVoid CTF 2026
Category: Cryptography

Exploits ECDSA nonce reuse (same k value) across two signatures to recover
the private key, then decrypts an AES-256-GCM encrypted flag.
"""

from Crypto.Cipher import AES
from Crypto.Util.number import inverse, long_to_bytes
import hashlib
import json


def main():
    # Load the challenge data
    with open("transcript.json", "r") as f:
        data = json.load(f)

    # secp256k1 curve order
    n = int(data["order_n"], 16)

    sigs = data["signatures"]

    # Find two signatures with the same r value
    r_values = {}
    for sig in sigs:
        r_hex = sig["r"]
        if r_hex in r_values:
            sig1 = r_values[r_hex]
            sig2 = sig
            print(f"[+] Found nonce reuse! Both signatures share r = {r_hex}")
            break
        r_values[r_hex] = sig

    # Extract values for the two colliding signatures
    r = int(sig1["r"], 16)
    s1 = int(sig1["s"], 16)
    z1 = int(sig1["sha256"], 16)
    s2 = int(sig2["s"], 16)
    z2 = int(sig2["sha256"], 16)

    print(f"[+] Signature 1: msg='{sig1['message']}'")
    print(f"[+] Signature 2: msg='{sig2['message']}'")

    # Recover the nonce k using the ECDSA nonce reuse formula:
    #   s1 = k^-1 * (z1 + r*d)  mod n
    #   s2 = k^-1 * (z2 + r*d)  mod n
    #   s1 - s2 = k^-1 * (z1 - z2)  mod n
    #   k = (z1 - z2) * (s1 - s2)^-1  mod n
    s_diff = (s1 - s2) % n
    z_diff = (z1 - z2) % n
    k = (z_diff * inverse(s_diff, n)) % n
    print(f"[+] Recovered nonce k = {hex(k)}")

    # Recover the private key d using:
    #   d = (s1 * k - z1) * r^-1  mod n
    r_inv = inverse(r, n)
    d = ((s1 * k - z1) * r_inv) % n
    print(f"[+] Recovered private key d = {hex(d)}")

    # Derive the AES-256 key from the private key
    priv_bytes = long_to_bytes(d)
    aes_key = hashlib.sha256(priv_bytes).digest()
    print(f"[+] Derived AES-256 key = {aes_key.hex()}")

    # Decrypt the encrypted flag using AES-256-GCM
    enc = data["encrypted_flag"]
    nonce = bytes.fromhex(enc["nonce"])
    tag = bytes.fromhex(enc["tag"])
    ciphertext = bytes.fromhex(enc["ciphertext"])
    aad = enc["aad"].encode()

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    print(f"\n[+] Flag: {plaintext.decode()}")
    return plaintext.decode()


if __name__ == "__main__":
    main()
