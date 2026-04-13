# Slavery - KashiCTF 2026 Forensics Writeup

## Challenge Info

- **Name:** `slavery`
- **Category:** `Forensics`
- **Flag format:** `kashiCTF{...}`

### Description

> Endless text. Endless effort. Endless suffering. Somewhere inside this Sanskrit manuscript, a flag has been hidden — buried deep enough to make anyone give up before reaching it. But that’s the whole point. Will you keep digging, or will the file break you first?

## TL;DR

The PDF was mostly a scanned manuscript, but one page had an extra hidden image overlay in the margin. Extracting that overlay revealed the flag directly:

---

## Initial Recon

The challenge provided a large PDF:

```text
Mantra Mahodadhi with Nauka Tika of Mahidhar by Jivanand Vidyasagar Bhattacharya 1892 - Siddheshvar Press Calcutta_compressed (1).pdf
```

Basic metadata checks:

```bash
pdfinfo "Mantra Mahodadhi with Nauka Tika of Mahidhar by Jivanand Vidyasagar Bhattacharya 1892 - Siddheshvar Press Calcutta_compressed (1).pdf"
exiftool "Mantra Mahodadhi with Nauka Tika of Mahidhar by Jivanand Vidyasagar Bhattacharya 1892 - Siddheshvar Press Calcutta_compressed (1).pdf"
```

Interesting observations:

- `pdfinfo` reported **408 pages**
- `pdftotext` produced almost nothing useful
- `pdffonts` showed only a minimal font entry
- `pdfimages -list` showed that the document was mostly just **page-sized scanned images**

That immediately suggested this was not a text-layer challenge. The flag was likely hidden in:

- PDF object structure
- an appended page/update
- an unusual embedded image
- a small overlay/watermark

---

## First Useful Lead: Page Count Weirdness

One suspicious inconsistency showed up early:

```bash
file "Mantra Mahodadhi with Nauka Tika of Mahidhar by Jivanand Vidyasagar Bhattacharya 1892 - Siddheshvar Press Calcutta_compressed (1).pdf"
pdfinfo "Mantra Mahodadhi with Nauka Tika of Mahidhar by Jivanand Vidyasagar Bhattacharya 1892 - Siddheshvar Press Calcutta_compressed (1).pdf"
```

`file` identified the PDF as having **20 pages**, while `pdfinfo` and `pdfimages` saw **408 pages**.

That strongly suggested the page tree had been modified or nested in a non-trivial way.

A quick raw search through the PDF confirmed that:

```bash
rg -a -n '/Type /Pages|/Count 20|/Count 400|/Count 408|/Type /Catalog' \
  "Mantra Mahodadhi with Nauka Tika of Mahidhar by Jivanand Vidyasagar Bhattacharya 1892 - Siddheshvar Press Calcutta_compressed (1).pdf"
```

Relevant findings:

- many internal `/Count 20` page-tree nodes
- one `/Count 400`
- one root `/Count 408`

So the PDF was basically built as:

- a large original block of pages
- plus an extra final branch containing 8 more pages

That made the tail of the document worth checking, but those pages still looked normal when rendered.

---

## Rendering and Structural Inspection

Since text extraction was dead, the next step was:

1. render suspicious pages
2. inspect page objects and content streams
3. look for any page that used more than the normal single scanned image

Most page content streams were tiny and looked like this after decompression:

```text
0.29876 0 0 0.29876 0 0 cm
/F1 20 Tf
q
1329 0 0 2271 0 0 cm
/X0 Do
Q
```

That means: "place one image on the page". Very standard for scanned PDFs.

So the solve became:

- find the page that does **not** follow this pattern

---

## The Breakthrough: `pdfimages -list`

The cleanest clue came from listing all embedded page images:

```bash
pdfimages -list "Mantra Mahodadhi with Nauka Tika of Mahidhar by Jivanand Vidyasagar Bhattacharya 1892 - Siddheshvar Press Calcutta_compressed (1).pdf"
```

One page stood out:

```text
268   267 image   648 1176 ... object 823 0
269   268 image   586 1176 ... object 826 0
269   269 image   928   87 ... object 828 0
270   270 image   745 1181 ... object 834 0
```

Page **269** had **two images**, not one:

- the normal manuscript page image: object `826`
- an additional narrow image: object `828` with dimensions **928x87**

That extra `928x87` image was extremely suspicious. It looked exactly like a hidden banner, strip, or watermark.

---

## Confirming the Suspicious Page Object

The page object for page 269 was:

```pdf
825 0 obj
<<
/Type /Page
/CropBox [0 0 281.427 564.647]
/MediaBox [0 0 281.427 564.647]
/Resources <<
/Font <<
/F1 4 0 R
>>
/XObject <<
/X268 826 0 R
/X0 828 0 R
>>
>>
/Contents [831 0 R 827 0 R 830 0 R]
/Parent 803 0 R
>>
endobj
```

This was different from normal pages because it referenced:

- `826 0 R` as the main scan
- `828 0 R` as an extra image object

The extra content stream `830` positioned `X0` with a weird transform:

```text
Q
q
q
0.000000000000000061232 1 -1 0.000000000000000061232 308 240 cm
q
124 0 0 11.625 -27.553 269.16 cm
/X0 Do
Q
Q
Q
```

That transform effectively rotates and places the overlay as a **thin vertical watermark** in the page margin.

---

## Extracting the Hidden Overlay

Object `828` was not a JPEG. It was a raw Flate-compressed RGB image:

```pdf
828 0 obj
<<
/Type /XObject
/Subtype /Image
/Width 928
/Height 87
/BitsPerComponent 8
/ColorSpace /DeviceRGB
/Filter /FlateDecode
/Length 829 0 R
>>
stream
...
endstream
endobj
```

So the easiest way to read it was:

1. decompress the stream
2. rebuild the raw RGB image
3. save it as PNG

Python snippet:

```python
from pathlib import Path
from PIL import Image
import zlib

raw = zlib.decompress(Path("/tmp/slavery_sus/obj828.bin").read_bytes())
img = Image.frombytes("RGB", (928, 87), raw)
img.save("obj828.png")
```

Once reconstructed, the hidden strip clearly contained the flag text.

---

## Visual Confirmation

Rendering page 269 also showed the same clue: a faint vertical Latin-text watermark in the left margin of an otherwise Sanskrit scan page.

So there were two good ways to solve it:

- visually inspect rendered page 269 and rotate/crop the margin text
- directly extract image object `828` and read the flag cleanly

The second method is much cleaner and more reliable.

---

## Flag

```text
kashiCTF{1r0nhex_1s_n07_4_m4n}
```

---

## Why This Challenge Works

This challenge is nice because it nudges solvers toward brute-forcing hundreds of pages, but the real solution is structural:

- the PDF is mostly boring repeated scan pages
- text extraction is intentionally useless
- the flag is hidden as a subtle margin overlay
- the decisive clue is that one page references an **extra image object**

So the trick is not "read everything", but "find what is different".

---

## Solver Notes

Useful commands during solving:

```bash
pdfinfo challenge.pdf
pdffonts challenge.pdf
pdftotext -layout challenge.pdf -
pdfimages -list challenge.pdf
rg -a -n '/Type /Pages|/Count|/Contents|/XObject' challenge.pdf
```

Most valuable indicators:

- page-count inconsistency
- image-only pages
- one page with an extra image object

If you are solving similar PDF forensics challenges in the future, `pdfimages -list` is one of the highest-signal commands to run early.
