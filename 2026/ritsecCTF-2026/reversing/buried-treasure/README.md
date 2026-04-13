# Buried Treasure - Writeup

## Challenge Info

- **Name:** `buried treasure`
- **Category:** `reversing`
- **Description:** `I buried the flag pretty deep, can you dig it back up?`
- **Flag format:** `RS{...}`

## TL;DR

The challenge binary is not a single checker. It is a chain of many tiny ELF wrappers, each decoding the next ELF and then transferring execution to it.

After recursively unpacking all layers, the final binary turns out to be a normal flag checker. It validates 36 input bytes with a simple arithmetic formula against a table stored in `.rodata`.

Inverting that formula gives the flag.

## Overview

At first glance the provided file looks like a small stripped static ELF:

```bash
file buried_treasure
```

Output:

```text
ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

Running it gives:

```bash
./buried_treasure
```

```text
enter the flag:
```

And for bad input:

```text
no :(
```

That looks simple, but the description is the real hint: the flag is "buried pretty deep". That turned out to be literal.

## Initial Recon

I started with normal triage:

```bash
file buried_treasure
readelf -S buried_treasure
strings -a buried_treasure | less
objdump -d -M intel buried_treasure | less
```

A few things stood out:

- The binary was static and stripped.
- The visible strings were mostly noise and runtime strings.
- The logic did not look like a direct checker.
- Large chunks of embedded data existed inside the binary.

Very quickly it became clear that this ELF was unpacking another ELF from embedded bytes.

So instead of treating it like one reversing problem, I treated it like a **recursive container format** problem.

## Big Picture

The challenge contains **15 nested ELF layers**.

Each layer decodes the next using one of three wrapper types:

1. `XOR`
2. `RC4-like stream cipher`
3. `Base64 blob`

The last layer is the actual checker.

## Recognizing the Wrapper Types

### 1. XOR wrapper

In these layers:

- the XOR key sits at file offset `0x240`
- the key length is `16` bytes
- the ciphertext begins at file offset `0x465`
- the output size can be recovered from the disassembly

The resulting plaintext starts with the ELF magic:

```text
7f 45 4c 46
```

### 2. RC4-like wrapper

These layers contained:

- key material at offset `0x240`
- a 256-byte initialization table at offset `0x260`
- ciphertext at an offset visible in the decrypt loop disassembly

The code was an RC4-style KSA + PRGA variant. Once decrypted, the next layer was again a valid ELF.

### 3. Base64 wrapper

These were the easiest layers. The `.data` section contained a large base64 string beginning with:

```text
f0VMRg
```

That decodes directly to bytes beginning with:

```text
7f454c46
```

which is just another ELF.

## Recursive Unpacking

I wrote a small recursive extractor that:

- identifies the wrapper type for the current layer
- extracts the next ELF
- repeats until no known wrapper remains

The unpack chain ended up being:

| Layer | Input | Output | Method | Output Size |
| --- | --- | --- | --- | --- |
| 0 | `buried_treasure` | `layer_1.bin` | XOR | `0x599a8` |
| 1 | `layer_1.bin` | `layer_2.bin` | XOR | `0x556c0` |
| 2 | `layer_2.bin` | `layer_3.bin` | RC4 | `0x512f8` |
| 3 | `layer_3.bin` | `layer_4.bin` | XOR | `0x4d010` |
| 4 | `layer_4.bin` | `layer_5.bin` | RC4 | `0x48c48` |
| 5 | `layer_5.bin` | `layer_6.bin` | Base64 | `0x334c0` |
| 6 | `layer_6.bin` | `layer_7.bin` | XOR | `0x2f1d8` |
| 7 | `layer_7.bin` | `layer_8.bin` | RC4 | `0x2ae10` |
| 8 | `layer_8.bin` | `layer_9.bin` | XOR | `0x26b28` |
| 9 | `layer_9.bin` | `layer_10.bin` | Base64 | `0x19be8` |
| 10 | `layer_10.bin` | `layer_11.bin` | RC4 | `0x15820` |
| 11 | `layer_11.bin` | `layer_12.bin` | XOR | `0x11538` |
| 12 | `layer_12.bin` | `layer_13.bin` | RC4 | `0xd170` |
| 13 | `layer_13.bin` | `layer_14.bin` | Base64 | `0x68a0` |
| 14 | `layer_14.bin` | `layer_15.bin` | XOR | `0x25b8` |
| 15 | `layer_15.bin` | final | actual checker | - |

At this point:

```bash
file /tmp/full_chain/layer_15.bin
```

reported a small static ELF, and unlike the previous layers it no longer looked like a decoder.

## Final Layer Recon

For the last layer:

```bash
readelf -S /tmp/full_chain/layer_15.bin
objdump -d -M intel /tmp/full_chain/layer_15.bin > /tmp/layer15.disasm
objdump -s -j .rodata /tmp/full_chain/layer_15.bin
```

Important facts:

- entry point: `0x201be8`
- real checker entry: `0x202c74`
- prompt string at `.rodata` address `0x200230`

The prompt was clearly visible:

```text
200230: 656e7465 72207468 6520666c 61673a20
         enter the flag:
```

The success and failure messages were not both visible in `strings`, which suggested some short dynamically-constructed output strings.

## Finding the Real Check Loop

The important code is in the final function beginning at `0x202c74`, especially the loop around `0x20301e`.

Relevant disassembly:

```asm
20301e: 49 f7 df              neg    r15
203021: 6a 26                 push   0x26
203023: 41 5c                 pop    r12
203025: 6a 0d                 push   0xd
203027: 41 5d                 pop    r13

203029: 49 83 fc 4a           cmp    r12,0x4a
20302d: 74 6a                 je     0x203099
20302f: 43 0f b6 44 26 da     movzx  eax,BYTE PTR [r14+r12*1-0x26]
203035: 49 0f af c5           imul   rax,r13
203039: 4c 01 e0              add    rax,r12
20303c: 4a 3b 04 e5 68 01 20  cmp    rax,QWORD PTR [r12*8+0x200168]
203043: 00
203044: 74 05                 je     0x20304b
203046: e8 e7 00 00 00        call   0x203132

20304b: 4b 8d 04 27           lea    rax,[r15+r12*1]
20304f: 48 ff c0              inc    rax
203052: 49 ff c4              inc    r12
203055: 49 83 c5 0d           add    r13,0xd
203059: 48 83 f8 26           cmp    rax,0x26
20305d: 75 ca                 jne    0x203029
```

### What this means

Before this loop, the code:

- reads user input into a 64-byte buffer
- strips newline / carriage return
- requires the final length to be exactly `0x24` bytes, which is `36`

Inside the loop:

- `r12` starts at `0x26`
- `r13` starts at `0x0d`
- input byte index is `r12 - 0x26`
- multiplier grows by `13` every iteration

So for character index `i` from `0` to `35`:

```text
input[i] * (13 * (i + 1)) + (0x26 + i) == table[i]
```

where `table[i]` is a `QWORD` from `.rodata`.

That means we can directly invert it:

```text
input[i] = (table[i] - (0x26 + i)) / (13 * (i + 1))
```

## Extracting the Table

The comparison table starts at:

```text
0x200168 + 0x26 * 8 = 0x200298
```

Using the final ELF on disk, I extracted the 36 qwords and inverted the formula.

Minimal solver:

```python
from pathlib import Path
import struct

data = Path("/tmp/full_chain/layer_15.bin").read_bytes()

# .rodata from readelf:
# addr = 0x2001d0, file offset = 0x1d0
RODATA_ADDR = 0x2001D0
RODATA_OFF = 0x1D0

table_addr = 0x200168 + 0x26 * 8
table_off = RODATA_OFF + (table_addr - RODATA_ADDR)

chars = []
for i in range(36):
    value = struct.unpack_from("<Q", data, table_off + i * 8)[0]
    ch = (value - (0x26 + i)) // (13 * (i + 1))
    chars.append(chr(ch))

print("".join(chars))
```

Output:

```text
RS{0k4y_i_th1nk_th47s_3n0ugh_l4y3rs}
```

## Sanity Check

To make sure this was not just a plausible-looking decode, I tested it against both:

- the final unpacked checker
- the original challenge binary

```bash
printf 'RS{0k4y_i_th1nk_th47s_3n0ugh_l4y3rs}\n' | /tmp/full_chain/layer_15.bin
printf 'RS{0k4y_i_th1nk_th47s_3n0ugh_l4y3rs}\n' | ./buried_treasure
```

Both printed:

```text
enter the flag: meow :D
```

So the recovered flag is definitely correct.

## Full Solve Strategy

If I had to summarize the intended solving path:

1. Notice that the binary is suspiciously small and stripped, with embedded data.
2. Realize it is decoding another ELF instead of checking the flag directly.
3. Identify the recurring wrapper families: XOR, RC4-like, and base64.
4. Recursively unpack until reaching a layer that stops behaving like a wrapper.
5. Reverse the final arithmetic checker.
6. Invert the comparison formula to reconstruct the flag.

## Takeaways

- Challenge descriptions matter. "Buried pretty deep" was the core hint.
- Static stripped ELFs with embedded blobs often mean packers, self-extractors, or staged loaders.
- Once a pattern repeats, it is often better to automate extraction than to reverse every layer manually.
- The final checker was much simpler than the nesting around it.

## Flag

```text
RS{0k4y_i_th1nk_th47s_3n0ugh_l4y3rs}
```
