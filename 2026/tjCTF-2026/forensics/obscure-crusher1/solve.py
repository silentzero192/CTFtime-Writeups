#!/usr/bin/env python3

from pathlib import Path


def xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def main() -> None:
    root = Path(__file__).resolve().parent
    blob = (root / "chall.bin").read_bytes()

    marker = b"lzmaKLZMA_DATA:"
    start = blob.index(marker) + len(marker)

    encrypted = blob[start:-4]
    key = b"icns\x01ttf\x02xylzmaK"
    flag = xor_repeat(encrypted, key).decode()
    print(flag)


if __name__ == "__main__":
    main()
