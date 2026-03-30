#!/usr/bin/env python3

import argparse
import base64
import io
import re
import sys
from pathlib import Path

from PIL import Image


FLAG_RE = re.compile(rb"VolgaCTF\{[^}]+\}")
DATA_URL_RE = re.compile(rb"data:image/png;base64,\s*([^\"'>\s]+)")


def load_png_bytes(path: Path) -> bytes:
    data = path.read_bytes()

    if path.suffix.lower() == ".png":
        return data

    match = DATA_URL_RE.search(data)
    if match:
        return base64.b64decode(match.group(1))

    raise ValueError(f"Could not find an inline PNG in {path}")


def get_indices(image: Image.Image) -> list[int]:
    getter = getattr(image, "get_flattened_data", None)
    if callable(getter):
        return list(getter())
    return list(image.getdata())


def extract_payload(png_bytes: bytes) -> bytes:
    image = Image.open(io.BytesIO(png_bytes))

    if image.mode != "P":
        raise ValueError(f"Expected a palette PNG, got mode {image.mode!r}")

    indices = get_indices(image)
    payload = bytearray()
    current = 0
    bit_count = 0

    for index in indices:
        current = (current << 1) | (index & 1)
        bit_count += 1
        if bit_count == 8:
            payload.append(current)
            current = 0
            bit_count = 0

    return bytes(payload)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract the hidden VolgaCTF flag from the Palo Arto challenge."
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Path to the challenge PNG or to an HTML/text file containing the inline base64 PNG.",
    )
    parser.add_argument(
        "--dump-payload",
        metavar="PATH",
        help="Optional path to save the recovered bitstream as raw bytes.",
    )
    args = parser.parse_args()

    if args.input:
        input_path = Path(args.input)
    elif Path("header.png").exists():
        input_path = Path("header.png")
    elif Path("index.html").exists():
        input_path = Path("index.html")
    else:
        print("No input file found. Provide a PNG or the saved HTML page.", file=sys.stderr)
        return 1

    try:
        png_bytes = load_png_bytes(input_path)
        payload = extract_payload(png_bytes)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.dump_payload:
        Path(args.dump_payload).write_bytes(payload)

    match = FLAG_RE.search(payload)
    if not match:
        print("Flag not found in recovered payload.", file=sys.stderr)
        return 1

    print(match.group().decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
