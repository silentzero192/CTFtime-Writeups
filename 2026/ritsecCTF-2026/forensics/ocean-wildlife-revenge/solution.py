#!/usr/bin/env python3

import json
import sqlite3
import struct
from pathlib import Path

from PIL import Image, ImageDraw


BAG_PATH = Path("mystery_message_0.db3")
OUTPUT_IMAGE = Path("recovered_flag.png")
FLAG = "RS{W4tch1ng_r0b0t_turtl3s}"


def decode_std_msgs_string(blob: bytes) -> str:
    length = struct.unpack("<I", blob[4:8])[0]
    return blob[8 : 8 + length - 1].decode()


def load_draw_commands(db_path: Path) -> list[dict]:
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "select data from messages where topic_id = 4 order by timestamp"
    ).fetchall()
    conn.close()
    return [json.loads(decode_std_msgs_string(data)) for (data,) in rows]


def render_commands(
    commands: list[dict],
    output_path: Path,
    width: int = 2200,
    height: int = 1400,
    scale: int = 180,
    margin: int = 80,
    line_width: int = 8,
) -> None:
    image = Image.new("L", (width, height), 0)
    draw = ImageDraw.Draw(image)

    pen_down = False
    current = None

    for command in commands:
        if command["cmd"] == "pen":
            pen_down = command["off"] == 0
            continue

        if command["cmd"] != "teleport":
            continue

        x = margin + command["x"] * scale
        y = height - (margin + command["y"] * scale)

        if current is not None and pen_down:
            draw.line((current[0], current[1], x, y), fill=255, width=line_width)

        current = (x, y)

    image.save(output_path)


def main() -> None:
    commands = load_draw_commands(BAG_PATH)
    render_commands(commands, OUTPUT_IMAGE)

    print(f"Recovered {len(commands)} draw commands from {BAG_PATH}")
    print(f"Rendered output image to {OUTPUT_IMAGE}")
    print(f"Flag: {FLAG}")


if __name__ == "__main__":
    main()
