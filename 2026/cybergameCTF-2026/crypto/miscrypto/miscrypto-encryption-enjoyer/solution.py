#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import argparse
import sys


# Stage 1 key: decrypts `encrypted` into the embedded PE payload.
KEY_STAGE1 = bytes.fromhex("ab31b3b2b132b4b0b932")

# Stage 2 key: decrypts the 0x29-byte payload buffer inside the PE.
KEY_STAGE2 = bytes.fromhex("af34f010992001")
PAYLOAD_OFFSET = 0x1E00
PAYLOAD_LEN = 0x29


def xor_repeating(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def recover_flag(encrypted: bytes) -> str:
    pe_blob = xor_repeating(encrypted, KEY_STAGE1)
    end = PAYLOAD_OFFSET + PAYLOAD_LEN
    if len(pe_blob) < end:
        raise ValueError(
            f"decrypted blob too small: need at least {end} bytes, got {len(pe_blob)}"
        )

    payload = pe_blob[PAYLOAD_OFFSET:end]
    flag_bytes = xor_repeating(payload, KEY_STAGE2)
    return flag_bytes.decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Solve miscrypto - encryption enjoyer"
    )
    parser.add_argument(
        "encrypted_file",
        nargs="?",
        default="encrypted",
        help="path to challenge encrypted file (default: ./encrypted)",
    )
    args = parser.parse_args()

    data = Path(args.encrypted_file).read_bytes()
    flag = recover_flag(data)

    if not (flag.startswith("SK-CERT{") and flag.endswith("}")):
        print(f"warning: decoded text does not look like a flag: {flag}", file=sys.stderr)

    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
