# Canvas Drift — 0xV01D CTF 2026 Writeup

**Category:** `Misc`  
**Difficulty:** `Medium`  
**Challenge Name:** `Canvas Drift`  

---

## Analysis

### Initial Reconnaissance

We're given a single file: `04_medium_lsb_canvas.zip`. Extracting it reveals a `canvas.ppm` file — a **Portable Pixmap** image in the raw binary format (P6).

```bash
$ unzip -l 04_medium_lsb_canvas.zip
Archive:  04_medium_lsb_canvas.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     9613  2026-05-17 12:01   canvas.ppm
```

### PPM File Structure

The PPM file uses the **P6** (raw RGB) format:

```
P6
80 40
255
<binary pixel data>
```

| Field       | Value         | Description                       |
|-------------|---------------|-----------------------------------|
| Magic       | `P6`          | Raw binary RGB pixel data         |
| Dimensions  | `80 40`       | 80 pixels wide, 40 pixels tall    |
| Max Value   | `255`         | 8-bit per channel RGB             |
| Pixel Data  | 9600 bytes    | 80 × 40 × 3 = 9600 RGB bytes      |

The header is 13 bytes, leaving exactly **9600 bytes** of pixel data — matching the expected `width × height × channels = 80 × 40 × 3`.

### Why LSB?

The challenge filename contains **`lsb_canvas`**, a strong hint toward **Least Significant Bit steganography**. In LSB steganography:

- The least significant bit of each pixel channel byte is replaced with a message bit
- Visually, the image appears nearly identical (maximum change of ±1 per channel)
- Up to `9600 bits` = `1200 characters` can be encoded in this image

---

## Solution

### Extraction Script

```python
with open('canvas.ppm', 'rb') as f:
    data = f.read()

# --- Parse PPM header ---
lines = data.split(b'\n', 3)
header_size = len(lines[0]) + 1 + len(lines[1]) + 1 + len(lines[2]) + 1
pixel_data = data[header_size:]

# --- Extract LSB from every byte ---
bits = []
for byte in pixel_data:
    bits.append(byte & 1)

# --- Reassemble bits into characters ---
chars = []
for i in range(0, len(bits) - 7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i + j]
    chars.append(chr(byte))

result = ''.join(chars)
print(result)
```

### How It Works

1. **Skip the header** — The first 13 bytes are the ASCII PPM header, not pixel data
2. **Extract LSBs** — Read the least significant bit (`byte & 1`) of every pixel channel byte
3. **Group into bytes** — Collect 8 bits at a time and convert to ASCII characters
4. **Result** — The flag appears at the start, followed by null padding

## Flag

```
0xV01D{LSB_PIXELS_TELL_STORIES}
```

---

## Key Takeaways

| Concept | Detail |
|---|---|
| **PPM Format** | P6 = raw binary RGB; header is ASCII text followed by binary pixel data |
| **LSB Steganography** | Embeds data in the least significant bit of each color channel — visually imperceptible |
| **Capacity** | An 80×40 RGB image holds 9600 bytes = 9600 bits = up to 1200 ASCII characters |
| **Detection** | Challenge filename hinted at LSB; in real scenarios, statistical analysis (chi-square test) can detect LSB embedding |
