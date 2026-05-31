# obscure crusher 1

- **Category:** Forensics
- **Flag:** `tjctf{0bscur3_crush3r_1cns_ttf_lzm3}`

## Challenge Description

A tiny binary that looks like one thing but is full of deliberate clues. The challenge text says you need **3 keys** to unlock it.

## Files

- `chall.bin` — 170 bytes; identified as `Mac OS X icon, "icns" type`

## Solution

### 1. Initial Analysis

```bash
$ file chall.bin
chall.bin: Mac OS X icon, 256 bytes, "icns" type
```

The file is only 170 bytes — far too small for a real `.icns`. Dumping the hex reveals several **visible string tokens** embedded in the binary:

```
00000000: 6963 6e73 0000 0100 6963 6e73 0100 0000  icns....icns....
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
...
00000050: 6500 0874 7466 0278 7900 0000 0000 0000  e..ttf.xy.......
...
00000070: 8000 6c7a 6d61 4b4c 5a4d 415f 4441 5441  ..lzmaKLZMA_DATA
00000080: 3a1d 090d 0767 0f44 0471 1b0c 1e49 3202  :....g.D.q...I2.
...
000000a0: 2713 0e5d 0e00 0000 00                   '..].....
```

The visible tokens are:

| Token    | Purpose                        |
|----------|--------------------------------|
| `icns`   | Fake file type                 |
| `\x01`   | Separator                      |
| `icns`   | Repeated                       |
| `\x01`   | Separator                      |
| (zeros)  | Padding                        |
| `name`   | "name" chunk marker            |
| `\x00`   | Null separator                 |
| `ttf`    | Second key token               |
| `\x02`   | Separator                      |
| `xy`     | Third key token                |
| (zeros)  | Padding                        |
| `lzmaK`  | LZMA prefix                    |
| `LZMA_DATA:` | Encryption marker          |
| (bytes)  | Encrypted payload              |
| `\x00\x00\x00\x00` | Trailing nulls         |

### 2. The Key Insight

The marker `lzmaKLZMA_DATA:` (at offset 0x74) immediately precedes the encrypted payload. The bytes after this marker are the **ciphertext**, and the four null bytes at the end are **not part of the payload**.

The **3 keys** mentioned in the challenge description are visible right in the binary:

1. `icns` — from the ICNS container header
2. `ttf` — from the "name" chunk's sub-type field
3. `xy` — from the trailing characters after `ttf`

Concatenated with their adjacent separator bytes, they form the XOR key:

```
icns\x01ttf\x02xylzmaK
```

### 3. Decrypt

The ciphertext is XORed with this repeating key:

```python
def xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))

encrypted = blob[start:-4]   # after "LZMA_DATA:", before trailing nulls
key = b"icns\x01ttf\x02xylzmaK"
flag = xor_repeat(encrypted, key).decode()
```

The plaintext is the flag directly — no further decoding needed.

## Full Solution Script

```python
#!/usr/bin/env python3

from pathlib import Path


def xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def main() -> None:
    root = Path(__file__).resolve().parent
    blob = (root / "chall.bin").read_bytes()

    marker = b"lzmaKLZMA_DATA:"
    start = blob.index(marker) + len(marker)

    encrypted = blob[start:-4]    # strip trailing nulls
    key = b"icns\x01ttf\x02xylzmaK"
    flag = xor_repeat(encrypted, key).decode()
    print(flag)


if __name__ == "__main__":
    main()
```

## Flag

```
tjctf{0bscur3_crush3r_1cns_ttf_lzm3}
```
