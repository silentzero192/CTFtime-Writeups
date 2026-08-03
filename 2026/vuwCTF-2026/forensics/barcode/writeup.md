# Barcode

| Field | Value |
| --- | --- |
| **Category** | Forensics |
| **Event** | VUW CTF 2026 |
| **Difficulty** | Medium |
| **Points** | 200 |
| **Flag** | `VuwCTF{this_paeth_guy_seems_kinda_cool}` |

> **Description:** I am told this used to be a QR code.

---

## Table of Contents

- [TL;DR](#tldr)
- [Initial Recon](#initial-recon)
- [Stage 1 — The Broken IHDR](#stage-1--the-broken-ihdr)
- [Stage 2 — 3393 ≠ 870: It's Not Grayscale](#stage-2--3393--870-its-not-grayscale)
- [Stage 3 — Undoing the PNG Filters](#stage-3--undoing-the-png-filters)
- [Stage 4 — Three Decoys and a Real QR](#stage-4--three-decoys-and-a-real-qr)
- [Solution Script](#solution-script)
- [Flag](#flag)
- [Key Takeaways](#key-takeaways)

---

## TL;DR

1. The PNG's **IHDR chunk has an invalid CRC**, so every standard image library refuses to open it.
2. The decompressed pixel data is **3393 bytes**, which is impossible for a 29×29 *grayscale* image (870 bytes) but exactly matches a 29×29 **RGBA** image — meaning the header's colour type was tampered with.
3. After manually undoing the PNG per-row filters, we find **R/G/B channels** all show an identical, **undecodable decoy QR code**.
4. The **alpha channel** is a completely different pattern — when treated as a black/white mask, it decodes to a valid QR code containing the flag.

---

## Initial Recon

```console
$ file barcode.png
barcode.png: PNG image data, 29 x 29, 8-bit grayscale, non-interlaced

$ ls -la
-rw-rw-r-- 1 jilani jilani  682 Aug  1 04:44 barcode.png
```

29×29 is exactly the module size of a **QR version 3** code. Small file, interesting. Let's see what's inside.

```console
$ python3 -c "from PIL import Image; Image.open('barcode.png')"
...
UnidentifiedImageError: cannot identify image file 'barcode.png'
```

That's suspicious. `file(1)` is happy but PIL throws `UnidentifiedImageError`. Normally PIL will open almost anything that looks like a PNG — even ones with errors — so a total rejection points at a corrupted *critical* chunk.

---

## Stage 1 — The Broken IHDR

Let's dissect the PNG chunk by chunk and check every CRC.

```python
import struct, binascii

data = open('barcode.png', 'rb').read()

def chunks(data):
    pos = 8
    while pos < len(data):
        length = struct.unpack('>I', data[pos:pos+4])[0]
        ctype  = data[pos+4:pos+8]
        cdata  = data[pos+8:pos+8+length]
        crc    = data[pos+8+length:pos+12+length]
        yield ctype, cdata, crc
        pos += 12 + length

for ctype, cdata, crc in chunks(data):
    ok = binascii.crc32(ctype + cdata) & 0xffffffff == struct.unpack('>I', crc)[0]
    print(ctype, 'crc_ok =', ok)
    if ctype == b'IHDR':
        w, h = struct.unpack('>II', cdata[:8])
        print('   w =', w, ' h =', h,
              ' bit_depth =', cdata[8],
              ' colour_type =', cdata[9],
              ' interlace =', cdata[12])
```

```text
b'IHDR' len 13 crc_ok = False     <-- !!!
b'pHYs' len 9  crc_ok = True
b'tEXt' len 25 crc_ok = True
b'IDAT' len 567 crc_ok = True
b'IEND' len 0  crc_ok = True
```

Only the **IHDR** (the chunk that declares width, height, bit depth and colour type) has a bad CRC. Everything else — including the actual image data in `IDAT` — is intact and checks out.

The header fields still parse:

- width = `0x1d` = **29**
- height = `0x1d` = **29**
- bit depth = **8**
- colour type = **0** (grayscale)

**Conclusion:** someone edited the IHDR fields and never recomputed the CRC. The declared *width/height/colour type* cannot be trusted. The truth is in the `IDAT` payload.

> **Digression — why did `file(1)` still call it a valid PNG?**
> `file(1)` only looks at the PNG signature (`89 50 4E 47 0D 0A 1A 0A`) and the IHDR layout; it doesn't verify CRCs. Image decoders that verify integrity (like PIL) reject it immediately.

---

## Stage 2 — 3393 ≠ 870: It's Not Grayscale

Decompress the `IDAT` payload with zlib:

```python
import struct, zlib

data   = open('barcode.png', 'rb').read()
pos    = data.find(b'IDAT')
length = struct.unpack('>I', data[pos-4:pos])[0]
raw    = zlib.decompress(data[pos+4:pos+4+length])

print(len(raw))   # -> 3393
```

**3393 bytes.** Now let's sanity-check that against the declared header.

For an 8-bit grayscale image (1 byte/pixel), each row of a PNG is:

```
row_bytes = 1 (filter type byte) + width
```

So a 29×29 grayscale image should be:

```
29 * (1 + 29) = 870 bytes
```

But we have **3393**. Not even close. So either the dimensions or the colour type are wrong. Factor 3393:

```
3393 = 29 * 117
     = 29 * (1 + 29*4)
```

which is exactly:

```
rows * (1 filter byte + 29 pixels * 4 bytes per pixel)
```

**The image is 29×29 RGBA (colour type 6), not grayscale (colour type 0).** The original IHDR said `colour_type = 0`, but it was really **6** (RGBA = 4 channels).

> This is a classic forensics manoeuvre: change `colour_type` from `6` to `0` and the CRC becomes invalid, breaking every automated tool. All the real info survives in the pixel data itself.

---

## Stage 3 — Undoing the PNG Filters

PNG pixel data is not stored raw: each row begins with a 1-byte **filter type** (0–4), and rows are *predicted* relative to previous bytes so they compress better. To recover true pixel values we must reverse the chosen predictor.

The five filter types:

| Type | Name | Predicted byte |
| --- | --- | --- |
| 0 | None | 0 |
| 1 | Sub | byte to the left (`x - a`) |
| 2 | Up | byte above (`x - b`) |
| 3 | Average | floor((a + b) / 2) |
| 4 | **Paeth** | adaptive predictor of a, b, c |

The fun part: this challenge's rows use **filter type 4 (Paeth)** — a hint that got literally baked into the flag later. Here's a full unfilter implementation for RGBA:

```python
import struct, zlib
import numpy as np

data   = open('barcode.png', 'rb').read()
pos    = data.find(b'IDAT')
length = struct.unpack('>I', data[pos-4:pos])[0]
raw    = zlib.decompress(data[pos+4:pos+4+length])

W, H, BPP = 29, 29, 4            # RGBA
stride = W * BPP

out = bytearray()
prev = bytearray(stride)         # row above, starts as zeros

for y in range(H):
    ftype = raw[0]
    raw = raw[1:]
    row = bytearray(raw[:stride])
    raw = raw[stride:]

    if ftype == 1:               # Sub
        for i in range(BPP, stride):
            row[i] = (row[i] + row[i - BPP]) & 0xff
    elif ftype == 2:             # Up
        for i in range(stride):
            row[i] = (row[i] + prev[i]) & 0xff
    elif ftype == 3:             # Average
        for i in range(stride):
            a = row[i - BPP] if i >= BPP else 0
            b = prev[i]
            row[i] = (row[i] + (a + b) // 2) & 0xff
    elif ftype == 4:             # Paeth
        for i in range(stride):
            a = row[i - BPP] if i >= BPP else 0
            b = prev[i]
            c = prev[i - BPP] if i >= BPP else 0
            p = a + b - c
            pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
            pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
            row[i] = (row[i] + pr) & 0xff

    out += row
    prev = row

mat = np.frombuffer(out, dtype=np.uint8).reshape(H, W, 4)
```

Now we have a real 29×29 RGBA pixel matrix.

---

## Stage 4 — Three Decoys and a Real QR

Extract each channel and render it as black/white:

```python
def channel_img(mat, c):
    ch = mat[:, :, c]
    return np.where(ch < 128, 0, 255).astype(np.uint8)   # dark -> black

for name, c in [('R', 0), ('G', 1), ('B', 2), ('A', 3)]:
    img = Image.fromarray(channel_img(mat, c)).resize((580, 580), Image.NEAREST)
    img.save(f'/tmp/opencode/{name}.png')
```

Decode each with `pyzbar`:

```python
from pyzbar.pyzbar import decode

for name in 'RGBA':
    result = decode(Image.open(f'/tmp/opencode/{name}.png'))
    print(name, result)
```

```text
R pyzbar: []                      # decoy, no decode
G pyzbar: []                      # decoy, no decode
B pyzbar: []                      # decoy, no decode
A pyzbar: [Decoded(data=b'VuwCTF{this_paeth_guy_seems_kinda_cool}', ...)]
```

What happened:

- **R, G, B** are identical copies of a perfectly finder-patterned QR code… that **never decodes**. It's a *trap* — visually it looks like the real QR, but its data/format area is garbage. If you just screen-grab it and scan it, you get nothing.
- The **alpha channel** is a *different* pattern entirely. Treating *opaque* (≥128) pixels as black yields a valid, scannable QR code.

That's the whole trick: the R/G/B channels are a plausible-looking decoy, while the actual payload lives in the transparency channel. A normal viewer composites RGBA over a background and shows you the RGB channels, so you're naturally pointed at the wrong QR. The alpha channel is invisible by default and has to be extracted deliberately.

---

## Solution Script

Putting it all together — `solve.py`:

```python
#!/usr/bin/env python3
import struct, zlib
import numpy as np
from PIL import Image
from pyzbar.pyzbar import decode

data = open('barcode.png', 'rb').read()
pos = data.find(b'IDAT')
length = struct.unpack('>I', data[pos-4:pos])[0]
raw = zlib.decompress(data[pos+4:pos+4+length])

W, H, BPP = 29, 29, 4
stride = W * BPP

out = bytearray()
prev = bytearray(stride)
for y in range(H):
    ftype = raw[0]; raw = raw[1:]
    row = bytearray(raw[:stride]); raw = raw[stride:]
    if ftype == 1:
        for i in range(BPP, stride):
            row[i] = (row[i] + row[i-BPP]) & 0xff
    elif ftype == 2:
        for i in range(stride):
            row[i] = (row[i] + prev[i]) & 0xff
    elif ftype == 3:
        for i in range(stride):
            a = row[i-BPP] if i >= BPP else 0
            b = prev[i]
            row[i] = (row[i] + (a+b)//2) & 0xff
    elif ftype == 4:
        for i in range(stride):
            a = row[i-BPP] if i >= BPP else 0
            b = prev[i]
            c = prev[i-BPP] if i >= BPP else 0
            p = a+b-c
            pa, pb, pc = abs(p-a), abs(p-b), abs(p-c)
            pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
            row[i] = (row[i] + pr) & 0xff
    out += row
    prev = row

mat = np.frombuffer(out, dtype=np.uint8).reshape(H, W, 4)

alpha = np.where(mat[:, :, 3] >= 128, 0, 255).astype(np.uint8)
img = Image.fromarray(alpha).resize((580, 580), Image.NEAREST)
img.save('alpha_qr.png')

for qr in decode(img):
    print(qr.data.decode())
```

```console
$ python3 solve.py
VuwCTF{this_paeth_guy_seems_kinda_cool}
```

---

## Flag

```
VuwCTF{this_paeth_guy_seems_kinda_cool}
```

---

## Key Takeaways

1. **Verify PNG chunk CRCs.** A broken IHDR CRC means the header lies — never trust width/height/colour type in a challenge file. The data payload is the source of truth.
2. **The byte count is the clue.** 3393 bytes cannot be 29×29 grayscale (870). Matching the count to `rows × (1 + width × bpp)` instantly reveals the real colour type.
3. **Don't forget PNG row filters.** Rows are predicted/encoded; you must reverse Sub/Up/Average/**Paeth** before the pixel values make sense. If PIL/OpenCV still fail after fixing the header, this is usually why.
4. **Alpha channels hide things.** RGB channels can be a perfectly valid-looking decoy while the real data sits in the alpha/transparency channel. Always inspect every channel independently.
5. **Steganography in the "invisible" channel** is a common CTF trick — challenge descriptions like *"used to be a QR code"* hint that the visible QR is a lie.

---

*Generated with love for VUW CTF 2026 Forensics.*
