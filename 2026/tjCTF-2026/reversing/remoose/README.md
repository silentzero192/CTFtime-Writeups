# Remoose

> **Category:** Reversing  
> **Description:** I changed just one little thing and my racing moose won't run anymore!

## Challenge Overview

We are given an x86-64 ELF binary (`chall`) that appears to be corrupted. The program, when fixed, outputs the flag character by character using individual `putchar` calls across multiple functions.

## Analysis

### 1. The "One Little Thing"

The file `chall` fails to execute. Checking the header reveals the problem:

```
$ xxd chall | head -1
00000000: 7f45 4c4b 0201 0120 2020 2020 2020 2020  .ELK...
```

The ELF magic is `\x7fELK` instead of the correct `\x7fELF` — byte 3 is `0x4b` ('K') instead of `0x46` ('F').

But that's not the only corruption. Examining further reveals that **every null byte (`0x00`) in the file has been replaced with a space character (`0x20`)**. This is the "one little thing" — a play on words: the author replaced "nothing" (null bytes) with "little things" (spaces).

| Before | After | Description                |
|--------|-------|----------------------------|
| 0x00   | 0x20  | Null → Space everywhere    |
| 0x46   | 0x4b  | Magic byte corrupted too   |

**Statistics:** 14,106 out of 16,808 bytes (84%) are `0x20` — zero null bytes remain.

### 2. Recovering the Binary

The fix is straightforward:

```python
fixed = bytearray(open('chall', 'rb').read())
for i in range(len(fixed)):
    if fixed[i] == 0x20:
        fixed[i] = 0x00
fixed[3] = 0x46  # Fix magic: 'K' → 'F'
```

We must be selective — not all `0x20` bytes were originally null. Some are legitimate instruction displacement values. For example, a `call putchar` instruction encodes as:

```
e8 20 fe ff ff    ; call 0x1030 (putchar)
```

Here `0x20` is part of the relative offset, NOT a corrupted null. Blindly replacing `0x20 → 0x00` would produce `e8 00 fe ff ff` which calls the wrong address (`0x1010`).

### 3. Reverse Engineering the Code

Using `capstone` on the fixed code section reveals the flag construction. The binary has these relevant symbols:

- `flag` — main flag function (prints "tjctf{")
- `flag2` — prints "m0", calls `flag4`
- `flag3` — prints "5m", calls `flag5`
- `flag4` — prints "0s3}", calls `printf`
- `flag5` — prints "a11_", calls `flag2`

#### Call Chain

```
flag → flag3 → flag5 → flag2 → flag4
```

#### Characters Printed by Each Function

**`flag` (0x117f):**
```asm
mov edi, 0x74    ; 't'
call putchar
mov edi, 0x6a    ; 'j'
call putchar
mov edi, 0x63    ; 'c'
call putchar
mov edi, 0x74    ; 't'
call putchar
lea rdi, [rip+0xe52]  ; "f{" at 0x2004
call printf            ; prints "f{"
call flag3
```

**`flag3` (0x11c9):**
```asm
mov edi, 0x35    ; '5'
call putchar
mov edi, 0x6d    ; 'm'
call putchar
call flag5
```

**`flag5` (0x1229):**
```asm
mov edi, 0x61    ; 'a'
call putchar
mov edi, 0x31    ; '1'
call putchar
mov edi, 0x31    ; '1'
call putchar
mov edi, 0x5f    ; '_'
call putchar
call flag2
```

**`flag2` (0x115a):**
```asm
mov edi, 0x6d    ; 'm'
call putchar
mov edi, 0x30    ; '0'
call putchar
call flag4
```

**`flag4` (0x11ee):**
```asm
mov edi, 0x30    ; '0'
call putchar
mov edi, 0x73    ; 's'
call putchar
mov edi, 0x33    ; '3'
call putchar
mov esi, 0x7d    ; '}'
lea rdi, [rip+0xdeb]  ; "%c\r" at 0x2007
call printf            ; prints "}"
```

#### Format Strings

The `__const` section contains two format strings:

| Address | Original Bytes | Interpretation |
|---------|---------------|----------------|
| 0x2004  | `66 7b 00 ...` | `"f{"` — opens the flag |
| 0x2007  | `25 63 0d 00 ...` | `"%c\r"` — prints the closing `}` + carriage return |

### 4. Building the Flag

Concatenating all characters in call order:

```
t  j  c  t  f  {  5  m  a  1  1  _  m  0  0  s  3  }
```

**Final flag: `tjctf{5ma11_m00s3}`**

This is leetspeak for **"small moose"** — fitting the "racing moose" theme from the challenge description:
- `5` = S, `ma11` = mall → **small**
- `m00s3` = m + oo (zeros) + s + e (three) → **moose**

## Flag

```
tjctf{5ma11_m00s3}
```
