# Administrative Tasks - Paragraphs

## Challenge Information

- **Category:** `Forensics`  
- **Challenge name:** `Administrative tasks - Paragraphs`  
- **Files provided:**
  - `Base64.docm`
  - `README2.txt`
  - `flag2.zip`
- **Flag format:** `SK-CERT{...}`

## Goal

Recover four hidden message fragments from the Office document, build the ZIP password using the order from the README, decrypt `flag2.zip`, and extract the flag.

## Initial Notes

The challenge README gives the core logic immediately:

```text
All parts are in format HIDDEN_MSG_x_{something}
The exact order is 4312
```

So the task is:

1. Find `HIDDEN_MSG_1_{...}`
2. Find `HIDDEN_MSG_2_{...}`
3. Find `HIDDEN_MSG_3_{...}`
4. Find `HIDDEN_MSG_4_{...}`
5. Build the password as:

```text
MSG_4 + MSG_3 + MSG_1 + MSG_2
```

Also, even though the README says `Base64.docx`, the actual file is `Base64.docm`, which is important because macro-enabled Office files can hide data both in XML parts and in VBA streams.

## Step 1: Unpack the DOCM

An Office `docm` file is just a ZIP container, so the first step is to unpack it:

```bash
unzip Base64.docm -d extracted_docm
```

After unpacking, the useful areas are:

- `word/document.xml`
- `word/footer1.xml`
- `word/vbaProject.bin`
- `word/media/`
- `word/_rels/document.xml.rels`

## Step 2: Recover `HIDDEN_MSG_2`

Searching `word/document.xml` for suspicious Base64-looking content reveals:

```text
SElEREVOX01TR18yX3s0N2QwMjQxYX0=
```

Decoding it:

```bash
base64 -d <<< 'SElEREVOX01TR18yX3s0N2QwMjQxYX0='
```

Output:

```text
HIDDEN_MSG_2_{47d0241a}
```

So:

```text
MSG_2 = 47d0241a
```

## Step 3: Recover `HIDDEN_MSG_3`

The document relationships show a footer is present:

```text
word/_rels/document.xml.rels -> footer1.xml
```

Inspecting `word/footer1.xml` shows tiny white text:

- color: `FFFFFF`
- size: `4`

This is classic "hidden in plain sight" formatting. Reassembling the text from the `<w:t>` nodes gives:

```text
HIDDEN_MSG_3_{5caf69d6}
```

So:

```text
MSG_3 = 5caf69d6
```

## Step 4: Recover `HIDDEN_MSG_4`

Because the file is a macro-enabled document, the VBA project is another obvious hiding place:

```text
word/vbaProject.bin
```

After extracting the OLE/VBA streams, the `README` stream contains a Base64 string:

```text
SElEREVOX01TR180X3sxZmYxNTE5Zn0=
```

Decode it:

```bash
base64 -d <<< 'SElEREVOX01TR180X3sxZmYxNTE5Zn0='
```

Output:

```text
HIDDEN_MSG_4_{1ff1519f}
```

So:

```text
MSG_4 = 1ff1519f
```

## Step 5: Recover `HIDDEN_MSG_1`

At this point, the missing fragment was `MSG_1`.

The `word/media/` directory contains many PNG files. A useful thing to check is whether all of them are actually referenced by the document relationships. `word/_rels/document.xml.rels` references images only up to `image38.png`, but the media folder also contains later images, including `image39.png`.

That makes `image39.png` suspicious.

### Why `image39.png` mattered

- It is not referenced from the main document relationships.
- Visually, it looks almost completely white.
- That is a common stego trick in Office challenges: place nearly-white text on a white background.

### Revealing the text

Cropping the suspicious region and applying a threshold makes the hidden text readable. One working approach is:

```python
from PIL import Image

img = Image.open("extracted_docm/word/media/image39.png").convert("L")
crop = img.crop((618, 273, 849, 289))
thr = crop.point(lambda p: 0 if p < 240 else 255)
thr = thr.resize((thr.width * 12, thr.height * 12))
thr.save("revealed_msg1.png")
```

After this processing, the text becomes readable as:

```text
HIDDEN_MSG_1_{03c77a9b}
```

So:

```text
MSG_1 = 03c77a9b
```

## Step 6: Build the ZIP Password

From the README, the order is `4312`, so:

```text
PASSWORD = MSG_4 + MSG_3 + MSG_1 + MSG_2
```

Substitute the recovered values:

```text
PASSWORD = 1ff1519f + 5caf69d6 + 03c77a9b + 47d0241a
```

Final password:

```text
1ff1519f5caf69d603c77a9b47d0241a
```

## Step 7: Decrypt `flag2.zip`

Test or extract the archive with the recovered password:

```bash
7z t -p1ff1519f5caf69d603c77a9b47d0241a flag2.zip
```

Then read the flag:

```bash
unzip -P 1ff1519f5caf69d603c77a9b47d0241a -p flag2.zip flag2.txt
```

## Recovered Fragments

| Fragment | Value |
|----------|-------|
| `MSG_1` | `03c77a9b` |
| `MSG_2` | `47d0241a` |
| `MSG_3` | `5caf69d6` |
| `MSG_4` | `1ff1519f` |

## Final Password

```text
1ff1519f5caf69d603c77a9b47d0241a
```

## Flag

```text
SK-CERT{M5W0RD_F0R3N51C5}
```

## Short Takeaway

This challenge hides data in several classic Office-forensics locations:

- document XML content
- footer formatting
- VBA project streams
- nearly invisible text inside an image

The key idea was to treat the `docm` as a container and inspect every likely hiding surface instead of focusing on only one technique.
