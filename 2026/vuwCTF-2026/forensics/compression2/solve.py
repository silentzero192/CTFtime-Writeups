#!/usr/bin/env python3
"""
VuwCTF 2026 - Forensics - "compression2"

compressed2.dat is a bit-level run-length encoded stream.
Every run is stored in a fixed-width 9-bit big-endian field:

    field = (run_length << 1) | bit_value

Runs strictly alternate (1s, 0s, 1s, ...) starting with a run of 1 bits.
Expanding the runs yields a PNG containing the flag.

Usage:  python3 solve.py [compressed2.dat] [flag.png]
"""

import sys

INFILE = sys.argv[1] if len(sys.argv) > 1 else "compressed2.dat"
OUTFILE = sys.argv[2] if len(sys.argv) > 2 else "flag.png"

FIELD_BITS = 9


def decode(raw: bytes) -> bytes:
    # Feed the whole file in as one big integer -> cheap MSB-first bit access.
    total_bits = len(raw) * 8
    acc = int.from_bytes(raw, "big")

    out_bits = []
    n_fields = total_bits // FIELD_BITS
    for i in range(n_fields):
        shift = total_bits - (i + 1) * FIELD_BITS
        field = (acc >> shift) & ((1 << FIELD_BITS) - 1)
        run_len, bit = field >> 1, field & 1
        out_bits.append(str(bit) * run_len)

    s = "".join(out_bits)
    s = s[: len(s) // 8 * 8]  # drop any trailing partial byte
    return int(s, 2).to_bytes(len(s) // 8, "big")


def encode(data: bytes) -> bytes:
    """Inverse transform - used to prove the decode is exact."""
    bits = bin(int.from_bytes(data, "big"))[2:].zfill(len(data) * 8)
    fields, i = [], 0
    while i < len(bits):
        j = i
        while j < len(bits) and bits[j] == bits[i]:
            j += 1
        fields.append(format(((j - i) << 1) | int(bits[i]), "09b"))
        i = j
    s = "".join(fields)
    s += "0" * (-len(s) % 8)
    return int(s, 2).to_bytes(len(s) // 8, "big")


if __name__ == "__main__":
    raw = open(INFILE, "rb").read()
    out = decode(raw)

    print(f"[+] input      : {len(raw)} bytes")
    print(f"[+] recovered  : {len(out)} bytes")
    print(f"[+] magic      : {out[:8].hex()}")
    print(f"[+] round-trip : {'OK (byte-identical)' if encode(out) == raw else 'MISMATCH'}")

    open(OUTFILE, "wb").write(out)
    print(f"[+] wrote      : {OUTFILE}")
