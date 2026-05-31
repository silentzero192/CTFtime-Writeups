# Thomas School of China

**Category:** Forensics  
**Flag:** `tjctf{c0ngr4ts_u_s0lv3d_my_f1st_CTF_chall!_btw_1_l1ke_b1rds}`  

## Challenge Description

> I infiltrated our rival counterpart in china and found this file on one of the computers... never heard of this filetype before... hm.

We're given a file called `chall.tsc` — a custom unknown file format with a `.tsc` extension.

---

## Solution

### Step 1: Initial Analysis

Running `file` tells us nothing useful — it's just recognized as `data`. A hex dump reveals the magic bytes:

```
00000000: 5453 4346 0100 0000 3c00 0000 3d00 0005  TSCF....<...=...
```

**Magic:** `TSCF` (the first 4 bytes).  
This is a custom image format. After the magic, the remaining header bytes likely encode image metadata. The rest of the file contains repeating byte patterns `db e9 cc` — which look like pixel data (RGB color `(219, 233, 204)`, a light pastel green).

### Step 2: Reverse-Engineering the Format

Analyzing the header structure:

| Offset | Bytes  | Value          | Meaning           |
|--------|--------|----------------|-------------------|
| 0–3    | `TSCF` | `0x54534346`   | Magic number      |
| 4–5    | `01 00`| `1` (LE 16-bit)| Version           |
| 6–7    | `00 00`| `0`            | Padding            |
| 8–9    | `3c 00`| `60` (LE 16-bit)| Width             |
| 10–11  | `00 00`| `0`            | Padding            |
| 12–13  | `3d 00`| `61` (LE 16-bit)| Height            |
| 14–16  | `00 05 39` | —          | Unknown/padding    |

So the header is **17 bytes**, and **pixel data starts at offset 17**.

File size check:
- Total: 14657 bytes
- Header: 17 bytes
- Pixel data: 14640 bytes
- Pixels: 60 × 61 = 3660 pixels
- Bytes per pixel: 14640 / 3660 = **4 bytes/pixel (RGBA)**

### Step 3: Extracting the Image

Write a Python script to parse the format and render the image:

```python
from PIL import Image
import numpy as np

data = open('chall.tsc', 'rb').read()
w, h = 60, 61

# Pixel data starts at offset 17 (header is 17 bytes)
rest = data[17:]
img_data = rest[:w * h * 4]

img = Image.frombytes('RGBA', (w, h), img_data)
img.save('chall.png')
```

This reveals a 60×61 image of a Chinese character on a green background:

![chall.png](chall.png)

The character is **鸟** (niǎo), meaning **"bird"** — a hint toward the flag content.

### Step 4: Finding the Hidden Text

The flag isn't visibly readable at such a low resolution. But looking at the non-background pixels, something unusual stands out — the RGB values themselves encode ASCII characters.

For example, these pixels appear in the image:

| Position | RGB Hex       | RGB Dec        | ASCII     |
|----------|---------------|----------------|-----------|
| (30,30)  | `0x74 0x6A 0x63` | (116, 106, 99) | `t`, `j`, `c` |
| (30,38)  | `0x74 0x66 0x7B` | (116, 102, 123)| `t`, `f`, `{` |
| (31,28)  | `0x63 0x30 0x6E` | (99, 48, 110)  | `c`, `0`, `n` |
| (31,34)  | `0x67 0x72 0x34` | (103, 114, 52) | `g`, `r`, `4` |

Each pixel's **R, G, and B channels each encode one ASCII character**. Reading them in scan order (top-to-bottom, left-to-right) and concatenating the three characters from each pixel reveals the flag.

### Step 5: Extracting the Flag

```python
from PIL import Image
import numpy as np

w, h = 60, 61
data = open('chall.tsc', 'rb').read()
rest = data[17:]
img = Image.frombytes('RGBA', (w, h), rest[:w*h*4])
pixels = np.array(img)

bg = (0xdb, 0xe9, 0xcc)
flag_chars = []

for y in range(h):
    for x in range(w):
        r, g, b, a = pixels[y, x]
        # Skip background pixels
        if (r, g, b) == bg:
            continue
        # Skip grayscale anti-aliasing pixels
        if r == g == b:
            continue
        # Only take pixels where all 3 channels are printable ASCII
        if all(32 <= v <= 126 for v in [r, g, b]):
            flag_chars.append((y, x, chr(r), chr(g), chr(b)))

# Sort in scan order (top-to-bottom, left-to-right)
flag_chars.sort(key=lambda p: (p[0], p[1]))

# Concatenate each pixel's R, G, B characters
flag = ''.join(rc + gc + bc for _, _, rc, gc, bc in flag_chars)
print(flag)
```

**Output:** `tjctf{c0ngr4ts_u_s0lv3d_my_f1st_CTF_chall!_btw_1_l1ke_b1rds}`

### Step 6: Decoding Leet Speak

The flag uses leet substitutions, which decode to a plaintext message:

| Leet     | Decoded |
|----------|---------|
| `c0ngr4ts` | congrats |
| `u`      | you      |
| `s0lv3d` | solved  |
| `f1st`   | first   |
| `chall!` | chall!  |
| `btw`    | btw     |
| `1`      | i       |
| `l1ke`   | like    |
| `b1rds`  | birds   |

> "congrats you solved my first CTF challenge! btw i like birds"

The Chinese character in the image (鸟 = bird) perfectly complements the flag's final phrase. The message is self-referential — this was the solver's first CTF challenge, and they just solved it.

---

## Summary

| Step | Description |
|------|-------------|
| 1 | Identify the custom `TSCF` magic bytes and reverse-engineer the image format |
| 2 | Parse the header (17 bytes) to get dimensions 60×61, 4 bytes/pixel (RGBA) |
| 3 | Extract and render the image — reveals Chinese character 鸟 (bird) |
| 4 | Notice non-background pixels have RGB values in printable ASCII range |
| 5 | Read each pixel's R, G, B as individual ASCII characters, sorted in scan order |
| 6 | Concatenate to get the flag with leet-speak encoding |

**Flag: `tjctf{c0ngr4ts_u_s0lv3d_my_f1st_CTF_chall!_btw_1_l1ke_b1rds}`**
