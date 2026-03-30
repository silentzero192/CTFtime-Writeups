#!/usr/bin/env python3

from __future__ import annotations

import argparse
import struct
from pathlib import Path


VERTEX_OFFSET = 0x44BBE0
VERTEX_COUNT = 0xEEE

# The program draws blocky glyphs with 6 vertices per filled rectangle.
GLYPH_MAP = {
    "..#../.##../#####/.##../.##../.##.#/..##.": "t",
    "....../....../.####./##..##/######/##..../.####.": "e",
    "......./......./##...##/.##.##./..###../.##.##./##...##": "x",
    "....../....../.#####/##..../.####./....##/#####.": "s",
    "......./......./.####../....##./.#####./##..##./.###.##": "a",
    "......./......./##...##/##.#.##/#######/#######/.##.##.": "w",
    "...###/..##../..##../###.../..##../..##../...###": "{",
    ".####./##..##/....##/..###./.##.../##..##/######": "2",
    ".##./..../###./.##./.##./.##./####": "i",
    "....../....../.####./##..##/##..../##..##/.####.": "c",
    "###..../.##..../.##.##./.###.##/.##..##/.##..##/###..##": "h",
    "..##../.###../..##../..##../..##../..##../######": "1",
    ".####./##..##/##..##/.#####/....##/...##./.###..": "9",
    ".####./##..##/##..##/.####./##..##/##..##/.####.": "8",
    "...###./..####./.##.##./##..##./#######/....##./...####": "4",
    ".#####./##...##/##..###/##.####/####.##/###..##/.#####.": "0",
    ".####./##..##/....##/..###./....##/##..##/.####.": "3",
    "######/##..../#####./....##/....##/##..##/.####.": "5",
    "###.../..##../..##../...###/..##../..##../###...": "}",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Recover the hidden flag from drawing.nro")
    parser.add_argument("path", nargs="?", default="drawing.nro", help="Path to the challenge NRO")
    parser.add_argument("--debug", action="store_true", help="Print decoded glyph patterns")
    return parser.parse_args()


def load_rectangles(data: bytes) -> list[tuple[float, float, float, float]]:
    values = struct.unpack_from("<" + "f" * VERTEX_COUNT * 6, data, VERTEX_OFFSET)
    rectangles: list[tuple[float, float, float, float]] = []

    for vertex_index in range(0, VERTEX_COUNT, 6):
        points = []
        for point_index in range(6):
            base = (vertex_index + point_index) * 6
            x = round(values[base], 9)
            y = round(values[base + 1], 9)
            points.append((x, y))

        xs = sorted({x for x, _ in points})
        ys = sorted({y for _, y in points})
        rectangles.append((xs[0], ys[0], xs[-1], ys[-1]))

    return rectangles


def infer_pitch(left_edges: list[float]) -> float:
    diffs = [round(left_edges[i + 1] - left_edges[i], 9) for i in range(len(left_edges) - 1)]
    candidates = [diff for diff in diffs if diff > 0.001]
    return min(candidates)


def build_grid(rectangles: list[tuple[float, float, float, float]]) -> list[list[int]]:
    left_edges = sorted({rectangle[0] for rectangle in rectangles})
    bottom_edges = sorted({rectangle[1] for rectangle in rectangles})

    pitch = infer_pitch(left_edges)
    min_x = min(left_edges)
    min_y = min(bottom_edges)

    col_count = max(round((x - min_x) / pitch) for x in left_edges) + 1
    row_count = max(round((y - min_y) / pitch) for y in bottom_edges) + 1

    grid = [[0 for _ in range(col_count)] for _ in range(row_count)]
    for x1, y1, _, _ in rectangles:
        col = round((x1 - min_x) / pitch)
        row = round((y1 - min_y) / pitch)
        grid[row][col] = 1

    return list(reversed(grid))


def extract_glyphs(grid: list[list[int]]) -> list[str]:
    rows = len(grid)
    cols = len(grid[0])
    blank_cols = [all(grid[row][col] == 0 for row in range(rows)) for col in range(cols)]

    glyphs: list[str] = []
    start = None
    for col in range(cols + 1):
        is_blank = True if col == cols else blank_cols[col]
        if not is_blank and start is None:
            start = col
        elif is_blank and start is not None:
            end = col
            glyph_rows = []
            for row in grid:
                glyph_rows.append("".join("#" if cell else "." for cell in row[start:end]))
            glyphs.append("/".join(glyph_rows))
            start = None

    return glyphs


def decode_flag(glyphs: list[str], debug: bool = False) -> str:
    decoded = []
    for index, glyph in enumerate(glyphs):
        char = GLYPH_MAP.get(glyph)
        if char is None:
            raise ValueError(f"Unknown glyph at index {index}: {glyph}")
        if debug:
            print(f"{index:02d}: {char} -> {glyph}")
        decoded.append(char)

    flag = "".join(decoded)
    if not flag.startswith("texsaw{") or not flag.endswith("}"):
        raise ValueError(f"Decoded text does not look like a texsaw flag: {flag}")
    return flag


def main() -> None:
    args = parse_args()
    data = Path(args.path).read_bytes()
    rectangles = load_rectangles(data)
    grid = build_grid(rectangles)
    glyphs = extract_glyphs(grid)
    flag = decode_flag(glyphs, debug=args.debug)
    print(flag)


if __name__ == "__main__":
    main()
