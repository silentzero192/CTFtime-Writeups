#!/usr/bin/env python3

C = 5740196029944570285461595789387642615026206835758048500685342416498085007060475130355254601538690350792607830802905
N = 17898028240830814136434787407852442663239728391134776310533753763258523791465145947321086853292608375964370070398263
E = 65537

# These factors were recovered from FactorDB.
P = 3471990687824593680273251255463630853556792715805318789409
Q = 5154975876978800665290208266910928152604080453168333003607


def is_printable_ascii(data: bytes) -> bool:
    return all(32 <= byte <= 126 for byte in data)


def recover_flag() -> bytes:
    assert P * Q == N

    phi = (P - 1) * (Q - 1)
    d = pow(E, -1, phi)
    residue = pow(C, d, N)

    prefix = b"SK-CERT{"
    suffix = b"}"
    prefix_int = int.from_bytes(prefix, "big")
    suffix_int = int.from_bytes(suffix, "big")
    suffix_len = len(suffix)
    inv_suffix_shift = pow(1 << (8 * suffix_len), -1, N)

    for total_len in range(len(prefix) + len(suffix), 128):
        middle_len = total_len - len(prefix) - len(suffix)
        prefix_term = prefix_int << (8 * (middle_len + suffix_len))
        middle_int = ((residue - prefix_term - suffix_int) * inv_suffix_shift) % N

        if middle_int >= (1 << (8 * middle_len)):
            continue

        middle = middle_int.to_bytes(middle_len, "big")
        candidate = prefix + middle + suffix

        if not is_printable_ascii(candidate):
            continue

        if pow(int.from_bytes(candidate, "big"), E, N) == C:
            return candidate

    raise ValueError("failed to recover a valid flag")


if __name__ == "__main__":
    print(recover_flag().decode())
