#!/usr/bin/env python3

import argparse
import re
import sys
import urllib.request
from pathlib import Path

from z3 import BitVec, Or, Solver, sat


URL = "https://css.ctf.ritsec.club/"
KEYBOARD = "0123456789QWERTYUIOPASDFGHJKL{_ZXCVBNM}"


def load_html(source: str | None) -> str:
    if source:
        return Path(source).read_text()

    with urllib.request.urlopen(URL) as response:
        return response.read().decode()


def extract_memory(html: str) -> bytes:
    matches = re.findall(
        r'@property --m(\d+) \{\s*syntax: "<integer>";\s*initial-value: (\d+);',
        html,
    )
    memory = {int(index): int(value) for index, value in matches}
    highest = max(memory)

    blob = bytearray(highest + 1)
    for index, value in memory.items():
        blob[index] = value

    return bytes(blob)


def parse_table(memory: bytes, offset: int, count: int) -> list[tuple[int, int, int, int]]:
    rows = []
    for i in range(count):
        base = offset + i * 8
        row = memory[base : base + 8]
        rows.append(
            (
                int.from_bytes(row[0:2], "little"),
                int.from_bytes(row[2:4], "little"),
                int.from_bytes(row[4:6], "little"),
                int.from_bytes(row[6:8], "little"),
            )
        )
    return rows


def solve_table(
    memory: bytes,
    table_offset: int,
    equation_count: int,
    length: int,
    prefix: str = "",
) -> str:
    table = parse_table(memory, table_offset, equation_count)
    allowed = [ord(c) for c in KEYBOARD]

    chars = [BitVec(f"c{i}", 16) for i in range(length)]
    solver = Solver()

    for char in chars:
        solver.add(Or(*[char == value for value in allowed]))

    for i, char in enumerate(prefix):
        solver.add(chars[i] == ord(char))

    for a, b, c, target in table:
        solver.add((chars[a] ^ (chars[b] + chars[c])) == target)

    if solver.check() != sat:
        raise RuntimeError("constraint system is unsatisfiable")

    model = solver.model()
    return "".join(chr(model[char].as_long()) for char in chars)


def validate(candidate: str, memory: bytes, table_offset: int, equation_count: int) -> bool:
    table = parse_table(memory, table_offset, equation_count)
    data = [ord(c) for c in candidate]
    return all((data[a] ^ (data[b] + data[c])) == target for a, b, c, target in table)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Solve the Cascading the Seven Seas CSS VM challenge."
    )
    parser.add_argument(
        "html",
        nargs="?",
        help="Optional local HTML file. If omitted, the script fetches the challenge URL.",
    )
    args = parser.parse_args()

    html = load_html(args.html)
    memory = extract_memory(html)

    q1 = solve_table(memory, 0x470, 10, 7)
    q2 = solve_table(memory, 0x420, 10, 5)
    flag = solve_table(memory, 0x320, 32, 32, prefix="RS{")

    print(f"Question 1 answer: {q1}")
    print(f"Question 2 answer: {q2}")
    print(f"Flag: {flag}")

    assert validate(q1, memory, 0x470, 10)
    assert validate(q2, memory, 0x420, 10)
    assert validate(flag, memory, 0x320, 32)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise
