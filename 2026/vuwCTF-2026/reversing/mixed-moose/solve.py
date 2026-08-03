#!/usr/bin/env python3
"""solve.py - Mixed Moose (VuwCTF 2026 reversing challenge)

The binary reads a 32-bit hex key, runs it through "Meesifier":

    Meesifier(x) = ((x ^ 0x5ABCDEF7) <<< 5) + 0x13371337   (mod 2^32)

and prints the flag as `VuwCTF{0x%05X}` with the original key when the
result equals the target 0x6ADB9A62.

This script reverses the transformation algebraically and verifies the
result by running the forward transform.
"""

MASK32 = 0xFFFFFFFF

XOR_KEY = 0x5ABCDEF7
ROTATE_AMOUNT = 5
ADD_KEY = 0x13371337
TARGET = 0x6ADB9A62


def rol32(value: int, amount: int) -> int:
    """Rotate a 32-bit value left by `amount` bits."""
    amount %= 32
    return ((value << amount) | (value >> (32 - amount))) & MASK32


def ror32(value: int, amount: int) -> int:
    """Rotate a 32-bit value right by `amount` bits."""
    amount %= 32
    return ((value >> amount) | (value << (32 - amount))) & MASK32


def meesifier(x: int) -> int:
    """Forward transform extracted from the Meesifier() function."""
    x ^= XOR_KEY
    x = rol32(x, ROTATE_AMOUNT)
    x = (x + ADD_KEY) & MASK32
    return x


def solve() -> int:
    """Invert Meesifier(x) == TARGET to recover x."""
    # 1. Undo the final add.
    y = (TARGET - ADD_KEY) & MASK32
    # 2. Undo the rotate-left-by-5 (same as rotate-right-by-5).
    y = ror32(y, ROTATE_AMOUNT)
    # 3. Undo the xor.
    x = y ^ XOR_KEY
    return x


def main() -> None:
    key = solve()

    # Verify the recovered key satisfies the check.
    assert meesifier(key) == TARGET, "inverse transform failed verification"

    print(f"[*] Meesifier({key:#010x}) == {meesifier(key):#010x}")
    print(f"[*] Flag: VuwCTF{{0x{key:05X}}}")


if __name__ == "__main__":
    main()
