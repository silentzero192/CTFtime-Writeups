#!/usr/bin/env python3
"""
Solution script for the vuwCTF-2026 misc challenge "fintech".

Flag format: VuwCTF{...}

The flag is hidden in the exponents of the values located in the column
immediately adjacent to the all-zero centre column of fintech.csv.
Each of those values is exactly 1E-(2 * ascii), so dividing the exponent
by two and converting to a character reveals the flag.

Usage: python3 solve.py
"""

import csv
import math


def solve(path: str = "fintech.csv") -> str:
    with open(path, newline="") as f:
        rows = [[float(x) for x in row] for row in csv.reader(f)]

    height = len(rows)
    width = len(rows[0])

    centre = width // 2  # index of the all-zero centre column
    assert all(rows[i][centre] == 0.0 for i in range(height))

    flag_chars = []
    for i in range(height):
        value = rows[i][centre - 1]
        exponent = -round(math.log10(abs(value)))
        flag_chars.append(chr(exponent // 2))

    return "".join(flag_chars)


if __name__ == "__main__":
    flag = solve()
    print(flag)
