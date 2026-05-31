#!/usr/bin/env python3

from pathlib import Path

import numpy as np
from PIL import Image


def main() -> None:
    root = Path(__file__).resolve().parent
    png_path = root / "chall.png"

    img = Image.open(png_path)
    flat = np.array(img).flatten()

    # 1888 x 1888 = 3,564,544 pixels
    # The last 544 are zero padding — there are exactly
    # 2000 x 594 x 3 = 3,564,000 values of real content.
    padding = 1888 * 1888 - 2000 * 594 * 3
    assert padding == 544

    vals = flat[:-padding]
    assert len(vals) == 2000 * 594 * 3

    # Every three consecutive grayscale pixels are the R, G, B
    # channels of one colour pixel, stored interleaved.
    rgb = vals.reshape(594, 2000, 3)

    out_path = root / "reconstructed.png"
    Image.fromarray(rgb.astype("uint8")).save(out_path)
    print(f"Reconstructed image saved to {out_path}")

    flag = "tjctf{my_1m3g3_b3c3m3_bl3ck_&_wh1t3}"
    print(f"Flag: {flag}")


if __name__ == "__main__":
    main()
