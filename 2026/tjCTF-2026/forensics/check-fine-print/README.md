# Check the Fine Print

- **Category:** `Forensics`  
- **Flag:** `tjctf{wow_you_actually_read_it}`

## Challenge Description

A PNG image that looks perfectly normal — until you inspect its metadata.

## Files

- `logo.png` — 150×150 RGBA PNG

## Solution

### 1. Initial Inspection

Standard tools reveal nothing unusual about the image itself, but `exiftool` reports **trailer data after `IEND`**. PNG files should end immediately after the `IEND` chunk; anything past that point is appended data.

```bash
exiftool logo.png
```

A quick scan with `binwalk` confirms a **ZIP archive** has been appended:

```bash
binwalk logo.png
```

### 2. Extract the Hidden ZIP

The ZIP magic bytes (`PK\x03\x04`) appear partway through the file. Extract the trailing blob:

```bash
# Find and extract the ZIP
tail -c +$((offset + 1)) logo.png > hidden.zip
```

Or programmatically:

```python
zip_magic = b"PK\x03\x04"
zip_offset = data.index(zip_magic)
zip_blob = data[zip_offset:]
```

### 3. Inspect the Extracted Files

The ZIP contains **248 tiny PNG files** named `001.png` through `248.png`, plus a `fixed/` subdirectory. Each tile is only ~50–250 bytes.

At first glance they look identical — numbered tiles in a grid. But some open correctly and others fail. The clue is in the **PNG IHDR compression method byte**.

### 4. The Key Insight

In a valid PNG, the IHDR chunk's compression-method byte (offset 26 from the start of the file) must be `0`. Several of these tiles have it set to `1`, making them intentionally malformed.

```python
# Tile 001.png: byte 26 = 0  (valid)
# Tile 002.png: byte 26 = 1  (malformed)
# Tile 003.png: byte 26 = 1  (malformed)
```

This is a **1-bit-per-tile encoding**:
- `0` at offset 26 → bit `0`
- `1` at offset 26 → bit `1`

### 5. Recover the Flag

Reading those 248 bits in filename order and grouping into bytes yields the flag:

```python
bits = []
for name in sorted(names):
    blob = (out_dir / name).read_bytes()
    bits.append("1" if blob[26] == 1 else "0")

bitstring = "".join(bits)
flag = bytes(int(bitstring[i:i+8], 2) for i in range(0, len(bitstring), 8)).decode()
# → "tjctf{wow_you_actually_read_it}"
```

## Full Solution Script

```python
#!/usr/bin/env python3

from pathlib import Path
import zipfile


def main() -> None:
    root = Path(__file__).resolve().parent
    png_path = root / "logo.png"
    data = png_path.read_bytes()

    # Extract the appended ZIP
    zip_magic = b"PK\x03\x04"
    zip_offset = data.index(zip_magic)
    zip_blob = data[zip_offset:]

    out_dir = root / "extracted"
    out_dir.mkdir(exist_ok=True)
    zip_path = out_dir / "hidden.zip"
    zip_path.write_bytes(zip_blob)

    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(out_dir)
        names = sorted(name for name in zf.namelist() if name.endswith(".png"))

    # Read one bit per tile from the IHDR compression-method byte
    bits = []
    for name in names:
        blob = (out_dir / name).read_bytes()
        bits.append("1" if blob[26] == 1 else "0")

    bitstring = "".join(bits)
    flag = bytes(
        int(bitstring[i : i + 8], 2) for i in range(0, len(bitstring), 8)
    ).decode()
    print(flag)


if __name__ == "__main__":
    main()
```
