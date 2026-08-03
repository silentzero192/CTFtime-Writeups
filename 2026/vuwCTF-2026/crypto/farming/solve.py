#!/usr/bin/env python3
"""
VuwCTF 2026 - Crypto / farming

The "field_recording" is a herd of lame cows: each cow is a moo that has
been run over by a tractor, so the letters m / o / O have been mangled into
M / O / o / 0 and grouped into words of variable length.

Reversing it:

  * Every word starts with the letter M (a cosmetic "marker").
  * The remaining letters form a base-3 number where
        O = 2    0 (zero) = 1    o = 1
    giving a byte value in 0..242.
  * Concatenating the bytes of all words yields a bzip2 stream (it begins
    with the magic bytes b'BZh91AY&SY').
  * Decompressing it prints an ASCII-moo banner containing the flag.

Run:
    python3 solve.py
"""

import bz2
from pathlib import Path


# base-3 digit mapping for the letters that follow the leading 'M'
DIGITS = {"O": 2, "0": 1, "o": 0}


def decode(words: list[str]) -> bytes:
    """Decode a list of 'cow' words into the raw (bzip2) byte stream."""
    data = bytearray()
    for word in words:
        if word[0] != "M":
            raise ValueError(f"unexpected word: {word!r}")
        value = 0
        for ch in word[1:]:
            value = value * 3 + DIGITS[ch]
        data.append(value)
    return bytes(data)


def main() -> None:
    here = Path(__file__).parent
    raw = (here / "field_recording").read_text().strip()
    words = raw.split()

    print(f"[*] {len(words)} cows in the field")

    bz2_data = decode(words)
    print(f"[*] decoded {len(bz2_data)} bytes, magic: {bz2_data[:10]!r}")

    assert bz2_data[:3] == b"BZh", "decoded data does not look like bzip2"

    plain = bz2.decompress(bz2_data)
    print(f"[*] decompressed {len(plain)} bytes:")
    print()
    print(plain.decode())


if __name__ == "__main__":
    main()
