#!/usr/bin/env python3
"""
VuwCTF 2026 - Crypto / concord

Vulnerability: the AES key schedule collapses to a one-parameter family.

The inner-loop operation

    op(a, b) = (a + 1) * (b + 1) % 257 - 1

is just multiplication in F_257 in disguise: with g(x) = x + 1 (mod 257),

    g(op(a, b)) = g(a) * g(b)   (mod 257)

so `op` is a conjugated group operation on the 256 non-zero elements of F_257.
That collapses the "impossibly slow" inner reduction over all 2^30 bytes to a
single constant:

    reduce(op, (op(x, b) for b in rand_input)) = P - 1

where P = prod(b + 1) mod 257 over every byte of rand_input (the x^N term
vanishes because g(x)^(2^30) = 1 for every byte x, since 2^30 = 0 mod 256).

Repeating `state = op(P - 1, state)` exactly 1023 * (j + 1) times gives

    key[j] = (P ^ (1023 * (j + 1)) - 1) mod 257

so the whole 32-byte AES key depends ONLY on P, and P lies in {1..256}.
Brute-force all 256 candidates and decrypt until the flag appears.

Run:
    python3 solve.py
"""

from Crypto.Cipher import AES

IV = bytes.fromhex("243f57341528c28727458b8cc5f52786")
CT = bytes.fromhex(
    "81df4fbb8ef58d5f6a7b4495706d76af"
    "5c5124160f15ec81015c24d3e6540c60"
    "4326da488ddb77e76ab73a6231ccd7ab"
)


def derive_key(P: int) -> bytes:
    """Reconstruct the 32-byte AES key from P = prod(b + 1) mod 257."""
    return bytes((pow(P, 1023 * (j + 1), 257) - 1) % 257 for j in range(32))


def main() -> None:
    for P in range(1, 257):
        key = derive_key(P)
        cipher = AES.new(key, AES.MODE_CBC, iv=IV)
        plaintext = cipher.decrypt(CT)
        if b"VuwCTF{" in plaintext:
            print(f"[+] P = {P}")
            print(f"[+] key = {key.hex()}")
            flag = plaintext.split(b"}")[0].decode() + "}"
            print(f"[+] flag = {flag}")
            return
    raise SystemExit("[-] flag not found")


if __name__ == "__main__":
    main()
