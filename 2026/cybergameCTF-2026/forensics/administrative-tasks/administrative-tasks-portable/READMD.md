# Administrative Tasks - Portable

## Challenge Information

- **Category:** `Forensics`
- **Challenge name:** `Administrative tasks - Portable`
- **Files provided:**
  - `PBES-512.pdf`
  - `README3.txt`
  - `flag3.zip`
- **Flag format:** `SK-CERT{...}`

## Goal

Recover the four hidden message fragments from the PDF, assemble the ZIP password using the order from `README3.txt`, decrypt `flag3.zip`, and extract the flag.

## Initial Observation

`README3.txt` gives the important rule:

```text
All parts are in format HIDDEN_MSG_x_{something}
The exact order is 4321
```

So once the fragments are found:

```text
PASSWORD = MSG_4 + MSG_3 + MSG_2 + MSG_1
```

This challenge is PDF-focused, so the likely hiding places are:

1. Embedded attachments
2. Signature data / PKCS#7 blob
3. Annotations / AcroForm objects
4. Images or appearance streams
5. Older revisions / object streams

## Step 1: Inspect the PDF

Useful first checks:

```bash
pdfinfo PBES-512.pdf
pdfsig PBES-512.pdf
pdfdetach -list PBES-512.pdf
```

Important findings:

- The PDF is **not encrypted**
- It contains an **AcroForm**
- It contains a **digital signature**
- `Page Mode: UseAttachments`
- It has **1 embedded file**

Attachment listing:

```text
1 embedded files
1: fonts.zip
```

So the PDF already tells us that attachments matter.

## Step 2: Recover `HIDDEN_MSG_4` from the Embedded Attachment

Extract the attachment:

```bash
pdfdetach -save 1 -o /tmp/fonts.zip PBES-512.pdf
7z l /tmp/fonts.zip
```

Contents:

```text
another_pass
another_part.zip
```

`another_pass` contains:

```text
verysecretpassword
```

Use that password on the nested ZIP:

```bash
7z x -so -pverysecretpassword /tmp/fonts_extracted/another_part.zip another_part.txt
```

Output:

```text
HIDDEN_MSG_4_{85add2c0}
```

So:

```text
MSG_4 = 85add2c0
```

## Step 3: Recover `HIDDEN_MSG_3` from the PDF Signature

The signature is real enough to be useful:

```bash
pdfsig PBES-512.pdf
```

Output shows:

- Signature field name: `Sig1`
- Hash algorithm: `SHA-512`
- Signature type: `adbe.pkcs7.detached`

The signature blob is stored in `/Contents <...>` inside the PDF. Searching the DER contents shows the hidden string encoded in the certificate data.

The relevant byte sequence decodes to:

```text
HIDDEN_MSG_3_{0a6899cf}
```

So:

```text
MSG_3 = 0a6899cf
```

This fits the challenge theme nicely: the “new encryption standard” PDF is signed with a SHA-512 PKCS#7 signature, and one fragment is hidden inside that signature material.

## Step 4: Recover `HIDDEN_MSG_2` from an Object Stream / Older PDF Object

This was the sneakiest fragment.

The PDF stores a large object stream (`1 0 obj`) containing many compressed indirect objects. Parsing that object stream reveals an annotation object whose `/Contents` holds the hidden message.

Recovered annotation payload:

```text
HIDDEN_MSG_2_{b100bf91}
```

The object content looks like this in simplified form:

```text
<<
  /Contents ( H
  I
  D
  D
  E
  N
  _
  M
  S
  G
  _
  2
  _
  {
  b
  1
  0
  0
  b
  f
  9
  1
  } )
>>
```

So:

```text
MSG_2 = b100bf91
```

## Step 5: Recover `HIDDEN_MSG_1` from Page 12 Image Glyphs

The last page contains a signature area and many tiny images. Running:

```bash
pdfimages -list PBES-512.pdf
```

shows a cluster of very small page-12 images. Extracting them reveals that they are individual character glyphs rather than normal illustrations.

Examples of the recovered glyph set:

```text
H I D E N _ M S G 1 { 4 a b c 6 9 f }
```

At first this only gives the **alphabet**, not the real string, because PDF image XObjects can be reused multiple times.

### Important detail

The characters are placed on page 12 using the page-12 content stream:

- **content stream:** `215 0 obj`
- **resource dictionary:** object `39`

Object `39` maps XObject names to glyph objects:

```text
/Im10 224 0 R
/Im11 225 0 R
/Im12 226 0 R
...
/Im24 238 0 R
/Im25 239 0 R
/Im6  240 0 R
/Im7  241 0 R
/Im8  242 0 R
/Im9  243 0 R
```

Then the page-12 stream places those glyphs left-to-right with repeated use of `D`, `_`, and `c`.

After sorting the glyph placements by X coordinate, the sequence becomes:

```text
HIDDEN_MSG_1_{4abcc69f}
```

So:

```text
MSG_1 = 4abcc69f
```

## Recovered Fragments

| Fragment | Source | Value |
|----------|--------|-------|
| `MSG_1` | page 12 glyph-image placements | `4abcc69f` |
| `MSG_2` | object stream annotation `/Contents` | `b100bf91` |
| `MSG_3` | PKCS#7 signature / certificate data | `0a6899cf` |
| `MSG_4` | embedded attachment chain | `85add2c0` |

## Step 6: Build the Password

The README says the order is `4321`, so:

```text
PASSWORD = MSG_4 + MSG_3 + MSG_2 + MSG_1
```

Substitute the values:

```text
PASSWORD = 85add2c0 + 0a6899cf + b100bf91 + 4abcc69f
```

Final password:

```text
85add2c00a6899cfb100bf914abcc69f
```

## Step 7: Decrypt `flag3.zip`

Test the password:

```bash
7z t -p85add2c00a6899cfb100bf914abcc69f flag3.zip
```

Then extract the flag:

```bash
unzip -P 85add2c00a6899cfb100bf914abcc69f -p flag3.zip flag3.txt
```

## Flag

```text
SK-CERT{WHY_15_MJ_3V3RYWH3R3}
```

## Short Takeaway

This challenge uses several different PDF hiding surfaces at once:

- embedded file attachments
- nested ZIPs and sidecar passwords
- PKCS#7 signature contents
- compressed object streams
- reusable image glyphs placed manually on the page

The biggest lesson is that a PDF is not just “text plus pictures.” It is a structured container with attachments, signatures, appearance streams, annotations, incremental updates, and object streams, all of which are excellent forensic hiding spots.
