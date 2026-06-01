#!/usr/bin/env python3
"""Forge the Edge448 signature that decrypts the Goldilocks flag."""
from handout import (
    BASE,
    MSG,
    IDENTITY,
    decode_point,
    effective_pub,
    challenge_scalar,
    scalar_mul,
    point_add,
    point_neg,
    encode_point,
    verify,
    decrypt_with_signature,
)

A_enc = effective_pub()
A = decode_point(A_enc)
assert scalar_mul(A, 4) == IDENTITY, "effective public key has order 4"


def find_signature(max_S: int = 1024):
    for S in range(max_S):
        S_point = scalar_mul(BASE, S)
        for c in range(4):
            R = point_add(S_point, point_neg(scalar_mul(A, c)))
            R_enc = encode_point(R)
            k = challenge_scalar(R_enc, A_enc, MSG)
            if k % 4 == c:
                sig = R_enc + S.to_bytes(57, "little")
                if verify(MSG, sig):
                    return S, c, k, sig
    raise RuntimeError("failed to forge signature")


if __name__ == "__main__":
    S, c, k, sig = find_signature()
    print("effective pub order", 4)
    print("chosen S", S)
    print("k mod 4", k % 4, "expected", c)
    print("signature", sig.hex())
    print("flag", decrypt_with_signature(sig).decode())
