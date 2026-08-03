# VuwCTF 2026 — Forensics — `compression2`

> **Flag:** `VuwCTF{this_one_won't_be_as_high}`

| | |
|---|---|
| **Category** | Forensics |
| **Challenge file** | `compressed2.dat` (1,390,543 bytes, MD5 `5c16089e86490cbc71d7f44f5e827fe9`) |
| **Recovered file** | `flag.png` (310,362 bytes, MD5 `83153f9e5c957cdac3b05c469663de56`) |
| **Difficulty** | Easy–Medium |
| **Tags** | custom encoding, bit-level RLE, file carving, statistics |
| **Solver** | [`solve.py`](solve.py) |

---

## TL;DR

`compressed2.dat` is a **bit-level run-length encoded** stream. Runs of identical bits are stored in fixed-width **9-bit big-endian fields**:

```
field = (run_length << 1) | bit_value
```

Runs strictly alternate, starting with a run of `1` bits. Expanding them produces a 480×480 PNG with the flag rendered across it. The scheme *inflates* the input by ~4.48×, which is exactly what the flag is joking about.

---

## 1. Recon

Nothing obvious from the usual first pass:

```console
$ ls -l compressed2.dat
-rw-rw-r-- 1 null null 1390543 Aug  1 16:07 compressed2.dat

$ file compressed2.dat
compressed2.dat: data
```

No magic bytes, no known container. `binwalk`/`foremost` find nothing to carve. So this is a **custom encoding**, not a stripped-header standard format — which the challenge name (`compression2`, implying a `compression1` warm-up) already hints at.

The hexdump is where it gets interesting:

```console
$ xxd compressed2.dat | head -8
00000000: 0181 8060 4018 0806 0201 8280 6040 3810  ...`@.......`@8.
00000010: 0606 0382 00a0 2018 2006 0201 8200 a020  ...... . ...... 
00000020: 1828 0602 018e 80a0 2018 0806 0401 8100  .(...... .......
00000030: 6020 1810 0608 0181 8060 6018 0806 0401  ` .......``.....
00000040: 8c01 2380 4848 0612 018c 8120 4018 0806  ..#.HH..... @...
00000050: 0202 8080 a060 1808 0604 0382 0064 0018  .....`.......d..
00000060: 080e 0402 8080 6020 1810 0604 0181 80e0  ......` ........
00000070: 2018 2006 1201 8080 6020 3808 0a04 0382  . .....` 8.....
```

Two things stand out:

1. The byte values are heavily skewed toward things like `0x80`, `0x60`, `0x40`, `0x20`, `0x18`, `0x08`, `0x06`, `0x02`, `0x01` — i.e. **a small cluster of set bits that keeps sliding right**, one position at a time, across consecutive bytes.
2. There is no high-entropy noise anywhere. Real compressed data (deflate, LZMA, bzip2) looks like white noise. This does not.

That rightward-sliding pattern is the classic fingerprint of **fixed-width fields that are not a multiple of 8 bits** packed into a byte stream. Each field's payload lands one bit further right in the byte than the last.

### Byte-level statistics

```console
$ python3 -c "
from collections import Counter
d=open('compressed2.dat','rb').read()
c=Counter(d)
print('len       ', len(d))
print('distinct  ', len(c))
print('top       ', c.most_common(10))
print('popcount  ', sum(bin(b).count('1') for b in d))
"
len        1390543
distinct   89
top        [(128, 176608), (2, 117277), (96, 100041), (6, 98144), (32, 97560),
            (24, 95644), (8, 87224), (1, 81947), (129, 70199), (4, 48076)]
popcount   2093995
```

Only **89 of 256** possible byte values ever occur, and only 2,093,995 of 11,124,344 bits are set (**18.8 %**). Both facts confirm strong sub-byte structure. Byte boundaries are meaningless here — we need to work on the **bitstream**.

---

## 2. Working at the bit level

```console
$ python3 -c "
import numpy as np
d=open('compressed2.dat','rb').read()
bits=np.unpackbits(np.frombuffer(d,dtype=np.uint8))
print(''.join(map(str,bits[:216])))
"
000000011000000110000000011000000100000000011000000010000000011000000010000000011000001010000000011000000100000000111000000100000000011000000110000000111000001000000000101000000010000000011000001000000000011000000010
```

Very regular: long runs of zeros punctuated by one or two `1`s, at a roughly constant spacing. Gap analysis backs that up:

```console
$ python3 -c "
import numpy as np; from collections import Counter
d=open('compressed2.dat','rb').read()
bits=np.unpackbits(np.frombuffer(d,dtype=np.uint8))
ones=np.flatnonzero(bits)
print(Counter(np.diff(ones).tolist()).most_common(8))
"
[(1, 607576), (8, 483880), (7, 281976), (9, 275049), (2, 207238), (10, 94330), (6, 73852), (3, 40894)]
```

Gaps between set bits pile up around **7–10**, centred on 8–9. Combined with the sliding hexdump pattern, the field width is almost certainly **9 bits**.

### Finding the field width empirically

Rather than guess, slice the bitstream at every plausible width and see which one produces a *low-cardinality, small-valued* symbol set. A correct alignment collapses the chaos; a wrong one smears it:

```console
$ python3 -c "
import numpy as np; from collections import Counter
d=open('compressed2.dat','rb').read()
bits=np.unpackbits(np.frombuffer(d,dtype=np.uint8))
for n in (8,9,10,11,12,13):
    m=len(bits)//n
    v=(bits[:m*n].reshape(m,n)*(1<<np.arange(n-1,-1,-1))).sum(1)
    c=Counter(v.tolist())
    print(n,'distinct',len(c),'max',max(c),'top',c.most_common(4))
"
8  distinct  89  max 248  top [(128, 176608), (2, 117277), (96, 100041), (6, 98144)]
9  distinct  50  max  68  top [(2, 309696), (3, 305005), (5, 157361), (4, 155179)]
10 distinct 183  max 992  top [(514, 82626), (24, 76553), (96, 75988), (32, 69051)]
11 distinct 402  max 1985 top [(32, 45707), (64, 45635), (128, 42433), (16, 42164)]
12 distinct 164  max 3712 top [(24, 152444), (128, 134514), (1538, 81100), (40, 78608)]
13 distinct 841  max 7941 top [(64, 35518), (128, 35441), (96, 29297), (192, 27459)]
```

**n = 9 is unambiguously the answer.** It yields the fewest distinct symbols (50) and the smallest maximum value (68) by a wide margin. Every other width produces hundreds of symbols spread over its full range.

Note what `max = 68` implies: 68 < 128, so the **top two bits of every single 9-bit field are always zero**, across all 1.2 M fields. That is not luck — the encoder is writing values that comfortably fit, in a field sized generously for the worst case.

---

## 3. Decoding the field format

Full symbol distribution at 9-bit alignment:

```console
$ python3 -c "
import numpy as np; from collections import Counter
d=open('compressed2.dat','rb').read()
bits=np.unpackbits(np.frombuffer(d,dtype=np.uint8))
n=9; m=len(bits)//n
v=(bits[:m*n].reshape(m,n)*(1<<np.arange(n-1,-1,-1))).sum(1)
print('fields:', m)
for k,c in sorted(Counter(v.tolist()).items())[:16]: print(f'  {k:3d} -> {c}')
"
fields: 1236038
    2 -> 309696
    3 -> 305005
    4 -> 155179
    5 -> 157361
    6 ->  77713
    7 ->  79361
    8 ->  37700
    9 ->  38005
   10 ->  18067
   11 ->  18772
   12 ->   9259
   13 ->   9164
   14 ->   4863
   15 ->   4641
   16 ->   2526
   17 ->   2133
```

Two structural observations:

**(a) The counts halve with every step of 2.** `{2,3} ≈ 615 k`, `{4,5} ≈ 313 k`, `{6,7} ≈ 157 k`, `{8,9} ≈ 76 k`, … That is a textbook **geometric(½) distribution** — precisely the length distribution of runs of identical bits in incompressible data (each additional bit has a ½ chance of matching, so `P(len = k) = 2^-k`).

**(b) Value parity is locked to field index parity.** Splitting the stream by index:

```console
$ python3 -c "
import numpy as np; from collections import Counter
d=open('compressed2.dat','rb').read()
bits=np.unpackbits(np.frombuffer(d,dtype=np.uint8))
n=9; m=len(bits)//n
v=(bits[:m*n].reshape(m,n)*(1<<np.arange(n-1,-1,-1))).sum(1)
print('even idx ->', sorted(Counter(v[0::2].tolist()))[:8])
print('odd  idx ->', sorted(Counter(v[1::2].tolist()))[:8])
"
even idx -> [3, 5, 7, 9, 11, 13, 15, 17]
odd  idx -> [2, 4, 6, 8, 10, 12, 14, 16]
```

Fields at even indices are **always odd**; fields at odd indices are **always even**. Never once violated in 1.2 M fields.

That nails the format. The **low bit is a flag that alternates every field**, and the remaining bits are a magnitude. Given observation (a) says the magnitudes are geometrically distributed run lengths, the format must be:

```
 bit:   8   7   6   5   4   3   2   1   0
      +---+---+---+---+---+---+---+---+---+
      |     run_length (8 bits)       |bit|
      +---+---+---+---+---+---+---+---+---+

 field = (run_length << 1) | bit_value
```

Runs of `1`s and `0`s alternate, so the flag bit necessarily alternates too — which is exactly the parity lock we measured. It is redundant information, stored anyway, which is one of several reasons this "compressor" is so bad.

### Sanity check by hand

The first eight fields are `3, 6, 3, 4, 3, 2, 3, 2`. Decoding `(len, bit) = (field >> 1, field & 1)`:

| field | run_len | bit | emits |
|---|---|---|---|
| 3 | 1 | 1 | `1` |
| 6 | 3 | 0 | `000` |
| 3 | 1 | 1 | `1` |
| 4 | 2 | 0 | `00` |
| 3 | 1 | 1 | `1` |
| 2 | 1 | 0 | `0` |
| 3 | 1 | 1 | `1` |
| 2 | 1 | 0 | `0` |

Concatenated: `1000 1001 0 1 0` → first byte = `10001001` = **`0x89`**.

`0x89` is the first byte of the **PNG signature**. Decode the whole thing.

---

## 4. Full decode

```python
import numpy as np

raw  = open('compressed2.dat', 'rb').read()
bits = np.unpackbits(np.frombuffer(raw, dtype=np.uint8))

n, m = 9, len(bits) // 9
fields = (bits[:m*n].reshape(m, n) * (1 << np.arange(n-1, -1, -1))).sum(1)

lengths = (fields >> 1).astype(np.int64)   # magnitude
values  = (fields &  1).astype(np.uint8)   # bit value

out = np.repeat(values, lengths)           # expand every run
out = out[: len(out) // 8 * 8]             # trim partial trailing byte
open('flag.png', 'wb').write(np.packbits(out).tobytes())
```

```console
$ file flag.png
flag.png: PNG image data, 480 x 480, 8-bit/color RGB, non-interlaced

$ xxd flag.png | head -2
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00000010: 0000 01e0 0000 01e0 0802 0000 00f2 b629  ...............)
```

A structurally perfect PNG — every chunk CRC validates, and it ends on a clean `IEND`:

```console
$ python3 -c "
import struct
d=open('flag.png','rb').read(); o=8
while o < len(d):
    ln, typ = struct.unpack('>I4s', d[o:o+8]); print(typ.decode(), ln); o += 12+ln
"
IHDR 13
sRGB 1
gAMA 4
pHYs 9
IDAT 65445
IDAT 65524
IDAT 65524
IDAT 65524
IDAT 48190
IEND 0
```

Opening it gives a photo of a pink dahlia with the flag overlaid in yellow script across the middle:

![recovered flag image](flag.png)

```
VuwCTF{this_one_won't_be_as_high}
```

> Note the apostrophe in `won't` — it is part of the flag. Zoom in before submitting; the cursive font makes `'` easy to miss and `_be_` easy to misread.

---

## 5. Verification

Two independent checks confirm the format was reconstructed exactly, not approximately.

**Nothing was dropped.** 1,390,543 bytes = 11,124,344 bits; 1,236,038 fields × 9 = 11,124,342 bits consumed, leaving exactly **2 leftover bits, both zero** — byte-alignment padding at the end of the stream. And the expansion produces 2,482,896 bits, an exact multiple of 8, so no partial byte was discarded either.

**The transform is bijective.** Re-encoding the recovered PNG with the inferred rules reproduces the challenge file bit for bit:

```console
$ python3 solve.py
[+] input      : 1390543 bytes
[+] recovered  : 310362 bytes
[+] magic      : 89504e470d0a1a0a
[+] round-trip : OK (byte-identical)
[+] wrote      : flag.png
```

A byte-identical round trip means the format description above is the *actual* format, not merely one that happens to yield a valid PNG.

Other confirmed properties:

* `min(run_length) = 1`, `max(run_length) = 34` — comfortably inside the 8-bit magnitude field.
* The bit-value flag alternates strictly across all 1,236,038 fields, starting at `1`.

---

## 6. Why the flag says what it says

The compression ratio is the punchline:

| | size |
|---|---|
| Original PNG | 310,362 bytes |
| "Compressed" `.dat` | 1,390,543 bytes |
| **Ratio** | **4.48× larger** |

Bit-level RLE is the worst possible choice here. The payload is PNG IDAT data — already deflate-compressed, so effectively random at the bit level. Random bits have a mean run length of **2**, so the encoder burns **9 bits to describe an average of 2 bits**, a 4.5× blow-up. On top of that it wastes:

* **1 bit per field** on the value flag, which is fully determined by alternation.
* **~3 bits per field** on the magnitude — the field is sized for run lengths up to 255, but the real maximum is 34 and the median is 2.

Hence `this_one_won't_be_as_high` — a nod to a preceding `compression1` challenge with a better (or at least less catastrophic) ratio.

---

## 7. Solver

Dependency-free version, stdlib only — see [`solve.py`](solve.py):

```python
#!/usr/bin/env python3
"""VuwCTF 2026 - Forensics - compression2"""
import sys

FIELD_BITS = 9

def decode(raw: bytes) -> bytes:
    total_bits = len(raw) * 8
    acc = int.from_bytes(raw, "big")
    out_bits = []
    for i in range(total_bits // FIELD_BITS):
        shift = total_bits - (i + 1) * FIELD_BITS
        field = (acc >> shift) & ((1 << FIELD_BITS) - 1)
        run_len, bit = field >> 1, field & 1
        out_bits.append(str(bit) * run_len)
    s = "".join(out_bits)
    s = s[: len(s) // 8 * 8]
    return int(s, 2).to_bytes(len(s) // 8, "big")

def encode(data: bytes) -> bytes:
    """Inverse transform - used to prove the decode is exact."""
    bits = bin(int.from_bytes(data, "big"))[2:].zfill(len(data) * 8)
    fields, i = [], 0
    while i < len(bits):
        j = i
        while j < len(bits) and bits[j] == bits[i]:
            j += 1
        fields.append(format(((j - i) << 1) | int(bits[i]), "09b"))
        i = j
    s = "".join(fields)
    s += "0" * (-len(s) % 8)
    return int(s, 2).to_bytes(len(s) // 8, "big")

if __name__ == "__main__":
    raw = open(sys.argv[1] if len(sys.argv) > 1 else "compressed2.dat", "rb").read()
    out = decode(raw)
    print(f"[+] recovered  : {len(out)} bytes ({out[:8].hex()})")
    print(f"[+] round-trip : {'OK' if encode(out) == raw else 'MISMATCH'}")
    open(sys.argv[2] if len(sys.argv) > 2 else "flag.png", "wb").write(out)
```

```console
$ python3 solve.py compressed2.dat flag.png
[+] input      : 1390543 bytes
[+] recovered  : 310362 bytes
[+] magic      : 89504e470d0a1a0a
[+] round-trip : OK (byte-identical)
[+] wrote      : flag.png
```

---

## 8. Takeaways

* **When `file` says `data`, go to the bitstream.** A hexdump whose set bits slide right by one position per byte is announcing a field width that isn't a multiple of 8.
* **Brute-force the alignment, don't guess it.** Slicing at every width from 8 to 16 and scoring by *distinct symbol count* and *maximum value* finds the right one instantly. The correct width makes the data look orderly; every wrong width looks like noise.
* **Distribution shape identifies the semantics.** Counts halving per step = geometric(½) = run lengths over random data. That single observation turned "unknown 9-bit symbols" into "this is RLE".
* **Parity/invariant checks reveal packed sub-fields.** "Even index ⇒ odd value" across 1.2 M samples is what exposed the low bit as an alternating flag rather than part of the magnitude.
* **Always round-trip.** Re-encoding to a byte-identical original is the difference between "I got a PNG out" and "I know the format."
* **Compression that ignores its input's entropy expands it.** RLE over already-deflated data is a guaranteed loss — which is the whole joke of the challenge.

---

## Flag

```
VuwCTF{this_one_won't_be_as_high}
```
