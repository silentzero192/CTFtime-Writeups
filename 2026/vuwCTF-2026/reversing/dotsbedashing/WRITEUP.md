# dotsbedashing — VuwCTF 2026 (Reversing)

> **Challenge:** dotsbedashing
> **Category:** Reversing
> **Description:** *A top secret encoded transmission has been captured! I bet it says something supeerrr dupeerrr important, if only we knew how to decode it :)*
> **Flag format:** `VuwCTF{...}`

---

## TL;DR

The binary hides the flag in a **Morse code transmission**. It keeps a global
32-bit value `g = 0xB1E1E1F1` that **rotates right by 1 for every character**,
XORs each character position with a table of encrypted 32-bit words, and
converts the result into Morse code (bit 1 = dash, bit 0 = dot). A quirk in the
comparison function means the checker only really verifies the **length** of
each Morse sequence, but the bit patterns still tell us the true message.

Decoding the XORed transmission gives the message

```
the 0 world 0 says 0 hii
```

where the Morse digit `0` (`-----`) is used as a **word separator**. The
program prints `VuwCTF{<input>}`, so the flag is:

**Flag: `VuwCTF{the0world0says0hii}`**

---

## Step 1 — Initial Recon

```console
$ file dotsbedashing
dotsbedashing: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically
linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
```

A stripped PIE with a small, suspicious import list:

```
puts      printf    strcmp    getline
time      exit      __stack_chk_fail
```

`strings` shows the whole user story:

```
Failed to read user input. Exiting...
Please enter a flag below!
 > Well done! You found the flag :) Please submit the following:
VuwCTF{%s}
Incorrect flag, please try again!
```

So the program reads a flag and, on success, prints `VuwCTF{%s}` — the flag is
**whatever string we type in**. We just need to figure out which 18-character
string satisfies the check.

---

## Step 2 — High-level Program Flow

`main` (0x12a2):

```c
int main(void) {
    char *line = NULL; size_t n = 0;
    printf("\nPlease enter a flag below!\n");

    if (getline(&line, &n, stdin) < 0) { puts("Failed to read user input..."); exit(1); }
    line[strlen(line) - 1] = 0;            // strip trailing newline

    if (check_flag(line)) {                // func_1352
        puts(" > Well done! You found the flag :) Please submit the following:");
        printf("VuwCTF{%s}", line);        // <-- flag = whatever we entered
    } else {
        puts(" > Incorrect flag, please try again!");
    }
    return 0;
}
```

All the work happens in `check_flag` (0x1352) and its helpers:

| Address  | Role |
|----------|------|
| `func_1352` | The flag checker (loop over chars / encrypted words) |
| `func_147c` | Character lookup: find table entry matching an input char |
| `func_14f8` | Decode a character out of a 4-byte table entry |
| `func_154a` | `g = ror32(g, 1)` — rotates the global key once per char |
| `func_15ac` | Compare the Morse strings of two values |
| `func_1637` | Convert a value into its Morse ("dot/dash") string |

---

## Step 3 — The Checker Loop (`func_1352`)

```asm
func_1352:                          ; bool check_flag(char *s)
    lea    rax, [rip+0x2d57]        ; &g_enc   (0x40c0)  -> ptr
    mov    [rbp-0x10], rax
    jmp    .cond

.next_char:
    call   time@plt                 ; (anti-debug timer setup)
    call   func_154a                ; g = ror32(g, 1)

    movzx  eax, BYTE [rsi]          ; c = *s
    mov    edi, eax
    call   func_147c                ; idx = lookup(c)
    mov    [rbp-0x18], eax
    cmp    DWORD [rbp-0x18], -1
    jne    .found
    xor    eax, eax                 ; char not in table -> FAIL
    jmp    .done

.found:
    mov    eax, [rax]               ; tmp = *ptr            (encrypted word)
    mov    edx, [rip+0x2cbc]        ; g   (0x40b0)
    xor    eax, edx                 ; tmp ^= g
    mov    [rbp-0x14], eax

    mov    edx, [rbp-0x18]          ; arg2 = idx
    mov    eax, [rbp-0x14]          ; arg1 = tmp
    call   func_15ac                ; ok = func_15ac(tmp, idx)
    xor    eax, 1
    test   al, al
    je     .continue                 ; ok != 1 -> FAIL

.continue:
    inc    QWORD [s]                ; s++
    add    QWORD [ptr], 4           ; ptr += 4

.cond:
    movzx  eax, BYTE [s]            ; while (*s != 0 && *ptr != 0)
    test   al, al
    je     .post
    mov    eax, [ptr]
    test   eax, eax
    jne    .next_char

.post:
    ; success only if BOTH *s == 0 AND *ptr == 0 (exact length match)
    ...
```

So for the flag to pass:

1. Each character must exist in the character table (func_147c).
2. For the `i`-th character, with `g` rotated once per position,
   `func_15ac(enc[i] ^ g, idx)` must return true.
3. The flag must be exactly as long as the encrypted table (18 entries).

---

## Step 4 — The Data Tables

The interesting data lives in `.data`:

```
# Character lookup table @ 0x4020  (36 x 4-byte entries, a-z and 0-9)
4020: 01 02 b0 01 08 04 4c 03 0a 04 36 04 04 03 91 06   ....L...6.....
4030: 00 01 59 02 02 04 33 05 06 03 ce 07 00 04 34 01   ..Y...3.......4.
4040: 00 02 96 04 07 04 53 05 05 03 6d 03 04 04 8d 03   ......S...m.....
4050: 03 02 b5 06 02 02 e6 04 07 03 ed 03 06 04 1c 02   ................
4060: 0d 04 2e 03 02 03 e4 07 00 03 e6 07 01 01 47 04   ..............G.
4070: 01 03 ea 07 01 04 9d 02 03 03 bb 05 09 04 0f 03   ................
4080: 0b 04 e5 06 0c 04 9e 02 1f 05 18 01 0f 05 98 01   ................
4090: 07 05 8c 02 03 05 99 01 01 05 43 04 00 05 a9 05   ..........C.....
40a0: 10 05 8d 02 18 05 6e 07 1c 05 07 03 1e 05 9c 01   ......n.........

# Global rotating key @ 0x40b0
40b0: f1 e1 e1 b1                     -> g = 0xB1E1E1F1

# Encrypted transmission @ 0x40c0  (18 x 4-byte entries)
40c0: f9 f1 f7 d8 7c 7c 7c 6c 3e 3d 35 36 00 1b 16 1b
40d0: 0c 0c 84 8d 80 84 ca c6 c1 c0 67 e3 e5 e5 bc f1
40e0: f4 f3 d9 f8 67 7d 64 7c 3c 3f 30 3e 1f 1c 1b 1f
40f0: 04 8b 88 0f 87 c4 c0 87 dc 66 eb c3 e1 b5 f5 e1
4100: f0 da fe f0 78 6e 7a 78
```

Reading the lookup table as 36 ints (and decoding each with `func_14f8`,
below) gives the characters `a b c d e f g h i j k l m n o p q r s t u v w x y z`
and `0 1 2 3 4 5 6 7 8 9` — no space, no braces. So the flag body is built
from lowercase letters and digits only.

---

## Step 5 — Decoding a Table Entry (`func_14f8`)

```asm
func_14f8:                          ; int  func_14f8(uint32_t v)
    mov    edi, [rbp-0x14]
    call   func_1563                ; A = (v >> 24) & 0xff
    mov    [rbp-0x2], al
    mov    edi, [rbp-0x14]
    call   func_1576                ; B = (v >> 16) & 0xff
    mov    [rbp-0x1], al

    ; esi = B ; edx = 8 - A
    mov    edx, 8
    sub    edx, eax                 ; edx = 8 - A
    mov    eax, esi
    mov    ecx, edx
    sar    eax, cl                  ; eax = B >> (8 - A)
    mov    esi, eax
    movzx  edx, BYTE [rbp-0x1]      ; B
    movzx  eax, BYTE [rbp-0x2]      ; A
    mov    ecx, eax
    shl    edx, cl                  ; edx = B << A
    mov    eax, edx
    or     eax, esi                 ; eax = rol8(B, A)
    ret
```

So an entry decodes to `char = rol8(byte2, byte3 mod 8)`. For example
`0x01 02 B0 01`: `rol8(0xB0, 1) = 0x61 = 'a'`.

Each entry also encodes the **Morse** for that character:

| byte | meaning |
|------|---------|
| `v & 0xff`      | Morse bit pattern (bit = 1 → dash, 0 → dot) |
| `(v >> 8) & 0xff` | Number of Morse symbols (1–5) |
| `(v >> 16) & 0xff` | The character, rotated |
| `(v >> 24) & 0xff` | Rotation amount |

This is a perfect **Morse code table**:

```
entry 0x01b00201 : a  -> bits 0x01 (1 sym)  = .
entry 0x04470101 : t  -> bits 0x01 (1 sym)  = -
entry 0x07e60300 : s  -> bits 0x00 (3 syms) = ...
entry 0x04430501 : 4  -> bits 0x01 (5 syms) = ....-
entry 0x0118051f : 0  -> bits 0x1f (5 syms) = -----
...
```

The low byte even matches standard Morse: `1` = dash. `s` = `...`, `o` = `---`,
`0` = `-----`, etc.

---

## Step 6 — The "Bug" in the Morse String Builder (`func_1637`)

`func_1637(value, out)` is meant to turn a value into a Morse string:

```asm
    mov    [rbp-0xa], (value >> 8) & 0xff   ; length
    mov    [rbp-0x9], value & 0xff          ; bit pattern
    mov    [rbp-0xc], length - 1            ; count
    mov    [rbp-0xb], 0                     ; j

.loop:                                      ; for count = length-1 .. 0
    movzx  edx, [rbp-0x9]                   ;   bit = (1 << count) & pattern
    mov    eax, [rbp-0xc]
    mov    esi, 1
    mov    ecx, eax
    shl    esi, cl
    mov    eax, esi
    and    eax, edx
    cmp    eax, 0xffffffd3                  ; <-- compare with -45 (!!)
    setne  cl
    mov    rdx, [rbp-0xb]                   ;   out[j] = (bit != -45)
    mov    rax, [rbp-0x20]
    add    rax, rdx
    mov    [rax], cl
    dec    [rbp-0xc]
    inc    [rbp-0xb]
    jns    .loop
```

`eax = (1 << count) & pattern` is always a small non-negative value
(`0, 1, 2, 4, ..., 128`). The comparison target is `0xffffffd3` (= −45), so the
two can **never** be equal, and `setne` **always yields 1**. Every symbol is
written as `0x01`; the actual dots and dashes never reach the output.

Consequently `func_15ac` (which `strcmp`s the two generated strings) passes
**iff both strings have the same length** — i.e. only the **Morse symbol
count** (`byte1`) of `tmp` and `idx` is really checked, never the pattern.

> Side observation: the author clearly meant `cmp eax, 0` (or to write the
> dot/dash characters directly); as written, the pattern comparison is dead
> code. It's also why this challenge is unusually permissive — several
> characters of the same Morse length pass each position. We still recover the
> intended message from the bit patterns themselves.

---

## Step 7 — Decoding the Transmission

`func_1352` gives us everything we need. For position `i` (0-based):

```
g_i  = ror32^i(0xB1E1E1F1, 1)
tmp  = enc[i] ^ g_i
bits = tmp & 0xff                      ; 1 = dash, 0 = dot
cnt  = (tmp >> 8) & 0xff               ; number of symbols
```

So we simply rotate `g` once per position, XOR with each encrypted word, and
read the low two bytes as a Morse sequence (MSB first, as the loop does):

| i | enc[i]        | g_i       | tmp ^ g_i  | cnt | bits | morse | char |
|---|---------------|-----------|------------|-----|------|-------|------|
| 0 | `0xd8f7f1f9` | …         | `0x00070101` | 1 | `01` | `-` | t |
| 1 | `0x6c7c7c7c` | …         | `0x00040400` | 4 | `00` | `....` | h |
| 2 | `0x36353d3e` | …         | `0x00090100` | 1 | `00` | `.` | e |
| 3 | `0x001b161b` | …         | `0x0008051f` | 5 | `1f` | `-----` | 0 |
| 4 | `0x0c0c848d` | …         | `0x000b0303` | 3 | `03` | `.--` | w |
| 5 | `0x8084cac6` | …         | `0x000d0307` | 3 | `07` | `---` | o |
| 6 | `0xc1c067e3` | …         | `0x00040302` | 3 | `02` | `.-.` | r |
| 7 | `0xe5e5bcf1` | …         | `0x000d0404` | 4 | `04` | `.-..` | l |
| 8 | `0xf4f3d9f8` | …         | `0x00010304` | 3 | `04` | `-..` | d |
| 9 | `0x7c647d67` | …         | `0x0008051f` | 5 | `1f` | `-----` | 0 |
|10 | `0x3c3f303e` | …         | `0x00060300` | 3 | `00` | `...` | s |
|11 | `0x1f1b1c1f` | …         | `0x00000201` | 2 | `01` | `.-` | a |
|12 | `0x0f888b04` | …         | `0x0005040b` | 4 | `0b` | `-.--` | y |
|13 | `0x87c0c487` | …         | `0x00060300` | 3 | `00` | `...` | s |
|14 | `0xdc66ebc3` | …         | `0x0008051f` | 5 | `1f` | `-----` | 0 |
|15 | `0xe1f5b5e1` | …         | `0x00040400` | 4 | `00` | `....` | h |
|16 | `0xf0fedaf0` | …         | `0x00060200` | 2 | `00` | `..` | i |
|17 | `0x787a6e78` | …         | `0x00060200` | 2 | `00` | `..` | i |

Concatenating the characters:

```
t h e 0 w o r l d 0 s a y s 0 h i i
```

That is `the0world0says0hii` — "the world says hii", with the Morse digit `0`
(`-----`) acting as a **word separator**.

---

## Step 8 — Verification

Entering the recovered string makes the binary print the flag:

```console
$ ./dotsbedashing
Please enter a flag below!
the0world0says0hii
 > Well done! You found the flag :) Please submit the following:
VuwCTF{the0world0says0hii}
```

---

## Step 9 — Solve Script

`solve.py` reads the tables straight out of the binary and decodes the
transmission:

```python
#!/usr/bin/env python3
"""dotsbedashing solver - decodes the hidden Morse transmission."""

import struct

BIN = "dotsbedashing"

MORSE = {
    "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.",
    "g": "--.", "h": "....", "i": "..", "j": ".---", "k": "-.-", "l": ".-..",
    "m": "--", "n": "-.", "o": "---", "p": ".--.", "q": "--.-", "r": ".-.",
    "s": "...", "t": "-", "u": "..-", "v": "...-", "w": ".--", "x": "-..-",
    "y": "-.--", "z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
}
MORSE_INV = {v: k for k, v in MORSE.items()}
MASK32 = 0xFFFFFFFF


def ror(v: int, n: int) -> int:
    n %= 32
    return ((v >> n) | (v << (32 - n))) & MASK32


def load_u32(addr, data, base):
    off = addr - base
    return struct.unpack("<I", data[off:off + 4])[0]


def main() -> None:
    with open(BIN, "rb") as f:
        f.seek(0x3000)                     # .data file offset of vaddr 0x4000
        section = f.read(0x110)

    g = load_u32(0x40B0, section, 0x4000)
    enc = [load_u32(0x40C0 + 4 * i, section, 0x4000) for i in range(18)]

    message = ""
    for e in enc:
        g = ror(g, 1)
        t = e ^ g
        bits = t & 0xFF                    # 1 = dash, 0 = dot
        cnt = (t >> 8) & 0xFF              # morse symbol count
        morse = "".join(
            "-" if (bits >> k) & 1 else "." for k in range(cnt - 1, -1, -1)
        )
        message += MORSE_INV.get(morse, "?")

    print(f"[*] morse transmission : {message}")
    print(f"[*] decoded message    : {message.replace('0', ' ')}")
    print(f"[+] FLAG               : VuwCTF{{{message}}}")


if __name__ == "__main__":
    main()
```

### Running it

```console
$ python3 solve.py
[*] morse transmission : the0world0says0hii
[*] decoded message    : the world says hii
[+] FLAG               : VuwCTF{the0world0says0hii}
```

---

## Key Takeaways

- **Morse in the data, not the code:** the "transmission" is a table of
  32-bit integers where the low byte is the dot/dash bit pattern and the next
  byte is the symbol count. The lookup table is literally the Morse alphabet
  (including digits).
- **A rotating global key:** `g` is rotated right once per character and XORed
  with each word before decoding — one layer of obfuscation on top of the
  Morse encoding.
- **Bugs leak information:** `cmp eax, 0xffffffd3` (comparing a bitmask with
  −45, always `setne`) dead-codes the pattern check, leaving only a length
  check. The real message still lives in the data — read the low bytes.
- **The flag format string is the spec:** `VuwCTF{%s}` means the flag is the
  exact string we feed the program; the checker just validates it.

---

**Flag: `VuwCTF{the0world0says0hii}`**
