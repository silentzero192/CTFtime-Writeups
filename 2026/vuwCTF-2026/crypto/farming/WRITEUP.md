# VuwCTF 2026 — Crypto / farming

> **Challenge**
> - **Category:** Crypto
> - **Name:** farming
> - **Description:** *My friend promised to give me a moose experience, but then left me with a herd of lame cows! Please save me*
> - **Flag format:** `VuwCTF{}`

## Files

| File              | Description                                      |
| ----------------- | ------------------------------------------------ |
| `field_recording` | The ciphertext: 148 "lame cows" (moos)          |
| `solve.py`        | Solver                                          |

## The file we are given

```
MO00o M0o0oo M0oO0O MOo0o M0O00 MO0oO M0ooOO M00oO M0oooO M0ooOO M0O0Oo
MO0oo M00OoO M0O Mo Mo M0oO0 M0o00O M00OoO M0000o M0O0OO M0o0Oo M0o0OO
M00OoO M0O M0oo Mo M0O M00 MOo0oo ...
```

A first glance: it *looks* like the [COW esoteric language](https://esolangs.org/wiki/COW)
(`moo`, `MOo`, `MoO`, ...), and the flavour text is full of cow jokes. But
there are three red flags:

1. There is **no lowercase `m`** anywhere (every token starts with an uppercase `M`).
2. There is a **digit `0`** mixed in — not part of the COW alphabet.
3. The "words" have **variable length** (2–7 chars), while every real COW
   instruction is exactly 3 characters.

If we feed it straight into a COW interpreter it just prints an error. So the
cows are literally **lame**: their moos (`m`, `o`, `O`) have been mangled.

---

## Recon

Let's get the structure:

```
148 words
each word starts with 'M'
remaining chars drawn from {O, o, 0}
```

The presence of exactly three symbols (`O`, `o`, `0`) behind the `M` is a
strong hint for **base-3**. Every word is `M` followed by a small base-3
number. If the word is a single byte, we should see byte values that make
sense when concatenated.

Trying the three symbol→digit assignments and rendering the resulting bytes
as text, one of them immediately pops out:

```
O=2  0=1  o=0    →   BZh91AY&SY.........
```

`BZh91AY&SY` is the **magic header of a bzip2 archive**! So:

> every word decodes to **one byte**, and the byte stream is a `bzip2` file.

That confirms the whole scheme:

| Symbol | Base-3 digit |
| ------ | ------------ |
| `O`    | 2            |
| `0`    | 1            |
| `o`    | 0            |

### Sanity check on the first three words

- `MO00o` → body `O00o` → digits `2 1 1 0` → `2·3³ + 1·3² + 1·3 + 0 = 66` → `'B'`
- `M0o0oo` → body `0o0oo` → `1 0 1 0 0` → `1·3⁴ + 0 + 1·3² + 0 + 0 = 90` → `'Z'`
- `M0oO0O` → body `0oO0O` → `1 0 2 1 2` → `81 + 0 + 18 + 3 + 2 = 104` → `'h'`

`BZh` ✔ — it really is bzip2.

---

## Decoding the whole stream

```python
DIGITS = {"O": 2, "0": 1, "o": 0}

data = bytearray()
for word in words:                 # e.g. "MO00o"
    value = 0
    for ch in word[1:]:            # skip the leading 'M' marker
        value = value * 3 + DIGITS[ch]
    data.append(value)             # one byte per cow
```

This yields **148 bytes** starting with the bzip2 magic:

```
b'BZh91AY&SY\x1a\x9c\xc1\x05\xb6\x04\xa5\xc4\xd8\xff\x1f...'
```

### Decompressing

```python
import bz2
plain = bz2.decompress(data)
```

which prints:

```
 _____________________________________
< VuwCTF{unfortunate_moos_experience} >
 -------------------------------------
  \
   \   \_\_    _/_/
    \      \__/
           (oo)\_______
           (__)\       )\/\
               ||----w |
               ||     ||
```

---

## Full solution

```python
#!/usr/bin/env python3
import bz2
from pathlib import Path

DIGITS = {"O": 2, "0": 1, "o": 0}

raw   = Path("field_recording").read_text().strip()
words = raw.split()

data = bytearray()
for word in words:
    value = 0
    for ch in word[1:]:
        value = value * 3 + DIGITS[ch]
    data.append(value)

assert data[:3] == b"BZh"
print(bz2.decompress(bytes(data)).decode())
```

### Output

```
[*] 148 cows in the field
[*] decoded 148 bytes, magic: b'BZh91AY&SY'
[*] decompressed 260 bytes:

 _____________________________________
< VuwCTF{unfortunate_moos_experience} >
 -------------------------------------
  \                                        ...
```

---

## Flag

```
VuwCTF{unfortunate_moos_experience}
```

---

## How I actually got there (the "moose" pun)

The description promised *"a moose experience"* but delivered *"a herd of
lame cows"*. That is the whole puzzle in one sentence:

- A moose's call is basically a **"moo"** — the COW programming language and
  the various "moo cipher" translators.
- But these cows are **lame** — the letters `m`/`o`/`O` of a real moo have been
  run through a tractor, turning some lowercase letters into `0` digits, and
  losing the distinction between `m` and `o` behind a leading `M`.

Once you stop trying to run it as COW and instead treat each word as a
`base-3` number, the bzip2 magic `BZh91AY&SY` falls out and the flag moos
itself at you.
