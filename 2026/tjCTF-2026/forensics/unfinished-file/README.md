# Unfinished File

**Category:** Forensics  
**Author:** (not specified)  
**Flag:** `tjctf{n3v3r_l3t_0ther_p30ple_t0uch_ur_c0mputer}`

## Challenge Description

> my stupid friend tried downloading this file before i shut my laptop down, what was he trying to do?

We are given a single file: `secret_archive.zip.crdownload`

## Solution

### Step 1: Identify the file type

The file has a `.crdownload` extension, which is used by Google Chrome for incomplete/partial downloads. A quick `file` command confirms it's generic data:

```bash
$ file secret_archive.zip.crdownload
secret_archive.zip.crdownload: data
```

### Step 2: Examine the file structure

Using `xxd` to hexdump the file reveals a clear structure:

```
00000000: 4352 444c 0100 0000 6b04 0000 0000 0000  CRDL....k.......
00000010: 2600 6874 7470 733a 2f2f 6578 616d 706c  &.https://exampl
00000020: 652e 636f 6d2f 7365 6372 6574 5f61 7263  e.com/secret_arc
00000030: 6869 7665 2e7a 6970 0000 0000 0000 0000  hive.zip........
...
00000100: 504b 0304 1400 0000 0000 0000 0000 ce9e  PK..............
```

The file is split into two parts:

1. **Chrome Download Metadata (bytes 0x00–0xFF):** Starts with the magic bytes `CRDL`, followed by metadata fields including the source URL: `https://example.com/secret_archive.zip`.

2. **Partial ZIP archive (bytes 0x100+):** Starts with `PK\x03\x04`, the standard ZIP local file header magic.

### Step 3: Recover the partial ZIP contents

Since this is a `.crdownload`, Chrome was in the middle of downloading a ZIP when the laptop was shut down. The ZIP header at offset `0x100` is intact, so we can extract whatever was already written.

Using `dd` to extract just the ZIP portion:

```bash
$ dd if=secret_archive.zip.crdownload bs=1 skip=256 of=partial.zip
```

Then listing the contents:

```bash
$ unzip -l partial.zip
Archive:  partial.zip
  Length      Date    Time    Name
---------  ---------- -----  ----
       41  00-00-1980 00:00   readme.txt
       47  00-00-1980 00:00   hidden/.flagdata
---------                     -------
       88                     2 files
```

The archive contains two files:

- `readme.txt` — a decoy message
- `hidden/.flagdata` — obfuscated data

```bash
$ cat readme.txt
This file is incomplete. Keep looking...

$ cat hidden/.flagdata
6(!6$9,q4q0..q6.r6*'0.2qr2.'.6r7!*.70.!r/276'0?
```

### Step 4: Decrypt the flag

The `hidden/.flagdata` content looks XOR-encrypted. Since the flag format is `tjctf{`, we can derive the XOR key:

| Plaintext | `t` (0x74) | `j` (0x6a) | `c` (0x63) | `t` (0x74) | `f` (0x66) | `{` (0x7b) |
|-----------|------------|------------|------------|------------|------------|------------|
| Ciphertext | 0x36 | 0x28 | 0x21 | 0x36 | 0x24 | 0x39 |
| **XOR Key** | **0x42** | **0x42** | **0x42** | **0x42** | **0x42** | **0x42** |

The key is `0x42` (ASCII `'B'`), applied as a single-byte XOR. Decrypting the full payload:

```python
data = bytes.fromhex('3628213624392c713471301d2e71361d72362a27301d327172322e271d367237212a1d37301d21722f32373627303f')
key = 0x42
decoded = bytes(b ^ key for b in data)
print(decoded.decode())
```

Output:
```
tjctf{n3v3r_l3t_0ther_p30ple_t0uch_ur_c0mputer}
```

### Step 5: (Bonus) The full decoy readme

Using the same XOR key on `readme.txt`'s content would reveal nothing special — it's plaintext. The real flag was hidden inside a `.flagdata` file within a `hidden/` directory inside the ZIP.

## Key Takeaways

- `.crdownload` files are Chrome partial downloads containing both metadata and partially downloaded content.
- Always examine the structure of unknown file types with a hex editor.
- Single-byte XOR is a common obfuscation technique in CTFs — known-plaintext attacks (like the flag format) easily break it.
- The flag itself is a good reminder: **never let other people touch your computer!**
