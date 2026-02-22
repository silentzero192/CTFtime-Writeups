#!/usr/bin/env python3
"""Solver for the polly's key reversing challenge."""

from __future__ import annotations

import hashlib
from collections import defaultdict


ENC_TREASURE = [
    76,
    77,
    65,
    83,
    67,
    121,
    85,
    100,
    48,
    94,
    91,
    48,
    53,
    102,
    82,
    55,
    97,
    73,
    111,
    123,
    61,
    52,
    76,
    116,
    95,
    116,
    58,
    123,
    119,
    54,
    120,
    127,
]

S_ARRAY = [
    0,
    2,
    3,
    4,
    0,
    2,
    6,
    2,
    2,
    2,
    2,
    3,
    9,
    8,
    0,
    11,
    17,
    13,
    11,
    16,
    14,
    20,
    6,
    19,
    6,
    13,
    26,
    1,
    1,
    28,
    15,
    1,
    14,
    9,
    14,
    29,
    3,
    7,
    23,
    26,
    9,
    0,
    41,
    3,
    30,
    11,
    1,
    20,
    10,
    2,
    27,
]


def perl_transform(value: int) -> int:
    # Mirrors Perl expression: (($_ - $c) . hex($_)) % 257 with $c == "0x10" (numeric 0).
    return int(f"{value}{int(str(value), 16)}") % 257


def ruby_allowed_chars() -> list[int]:
    # Ruby's modular check keeps chars where (char - 0x10) has multiplicative order 256 mod 257.
    allowed = []
    for c in range(33, 127):
        if c == 94:
            continue
        if pow((c - 16) % 257, 128, 257) != 1:
            allowed.append(c)
    if len(allowed) != 50:
        raise RuntimeError(f"expected 50 Ruby-allowed chars, got {len(allowed)}")
    return allowed


def build_rank_from_sarray() -> list[int]:
    # S_ARRAY is the insertion-sort inversion vector for the transformed Perl bytes.
    order = [0]
    for i, inv in enumerate(S_ARRAY):
        n = i + 1
        order.insert(n - inv, n)

    rank = [0] * len(order)
    for pos, idx in enumerate(order):
        rank[idx] = pos
    return rank


def build_candidates() -> dict[int, list[int]]:
    allowed = ruby_allowed_chars()
    # Perl receives two extra trailing bytes because of its parsing quirks.
    universe = allowed + [10, 47]

    transformed_to_values: dict[int, list[int]] = defaultdict(list)
    for c in universe:
        transformed_to_values[perl_transform(c)].append(c)

    sorted_outputs = sorted(perl_transform(c) for c in universe)
    rank = build_rank_from_sarray()

    candidates: dict[int, list[int]] = {}
    for idx in range(52):
        transformed = sorted_outputs[rank[idx]]
        candidates[idx] = transformed_to_values[transformed][:]
    return candidates


def check_order_constraints(key_bytes: list[int]) -> bool:
    pos = {value: idx for idx, value in enumerate(key_bytes)}
    constraints = [
        (79, 112),
        (69, 102),
        (99, 70),
        (96, 56),
        (54, 117),
        (64, 117),
        (123, 55),
    ]
    return all(pos[a] < pos[b] for a, b in constraints)


def enumerate_keys(candidates: dict[int, list[int]]) -> list[str]:
    allowed_set = set(ruby_allowed_chars())
    key_candidates = {i: candidates[i] for i in range(50)}

    current = [None] * 50
    used: set[int] = set()
    to_fill = []
    for i in range(50):
        vals = key_candidates[i]
        if len(vals) == 1:
            val = vals[0]
            current[i] = val
            used.add(val)
        else:
            to_fill.append(i)

    results: list[str] = []

    def dfs(k: int) -> None:
        if k == len(to_fill):
            key_bytes = [int(x) for x in current]
            if set(key_bytes) != allowed_set:
                return
            if not check_order_constraints(key_bytes):
                return
            results.append("".join(chr(x) for x in key_bytes))
            return

        idx = to_fill[k]
        for val in key_candidates[idx]:
            if val in used:
                continue
            used.add(val)
            current[idx] = val
            dfs(k + 1)
            current[idx] = None
            used.remove(val)

    dfs(0)
    return results


def decrypt_flag(key: str) -> str:
    digest_nibbles = [int(ch, 16) for ch in hashlib.md5(key.encode()).hexdigest()]
    return "".join(chr(digest_nibbles[i] ^ ENC_TREASURE[i]) for i in range(32))


def main() -> None:
    candidates = build_candidates()
    possible_keys = enumerate_keys(candidates)
    if not possible_keys:
        raise RuntimeError("no key candidates found")

    chosen_key = None
    chosen_flag = None
    for key in possible_keys:
        flag = decrypt_flag(key)
        if flag.startswith("BCCTF{") and flag.endswith("}"):
            chosen_key = key
            chosen_flag = flag
            break

    if chosen_key is None:
        chosen_key = possible_keys[0]
        chosen_flag = decrypt_flag(chosen_key)

    print(f"[+] key  : {chosen_key}")
    print(f"[+] flag : {chosen_flag}")


if __name__ == "__main__":
    main()
