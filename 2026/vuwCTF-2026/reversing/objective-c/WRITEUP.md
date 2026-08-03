# VuwCTF 2026 — objective-c (Reversing)

> **Category:** Reversing
> **Flag format:** `VuwCTF{...}`
>
> *"I found these poor despondent moose on the side of the road, and the vet just
> muttered something about 'objects' and C, and I know they didn't mean C++.
> Please help these moose in these trying times"*

| Files | `cow`, `calf` (both 1528 bytes) |
| --- | --- |
| **Final Flag** | `VuwCTF{a_family_linked_at_last}` |

---

## TL;DR

* We are given **two relocatable ELF object files** (`.o`) — that is the whole
  "objects" + C (and **not** C++) hint.
* The files are named after a mother moose (`cow`) and her baby (`calf`), and
  their code is **mutually recursive**: `cow` calls `calf`, which calls `cow`…
* Each function XORs one flag byte against a running key and compares it against
  a byte in its own `.data` section. The two 16-byte tables interleave.
* Emulating the recursion and pinning the initial key so the output starts with
  `VuwCTF{` recovers the whole flag.

---

## 1. Initial triage

```bash
$ file cow calf
calf: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped
cow:  ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped

$ strings cow
92ROgP\CU@G|[ImA
Eurrgh!
Eurrgh

$ strings calf
6^cXRXYrFJB@XXm
eurm...
erm
```

`ELF … relocatable` means these are **unlinked object files** (`.o`). Combined
with the description, "**objects**" and C, "**they didn't mean C++**" — the hint
is *object files*, and the moose family (cow + calf) are the two objects.

A `readelf -a` shows a single global symbol each:

```
Symbol table '.symtab' contains 2 entries:
  0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
  1: 0000000000000000   180 FUNC    GLOBAL DEFAULT    1 cow
```

…and **no relocations**. The `.rela` sections were stripped, so all the
`call`/`lea [rip+0]` operands are zeroed out — the code cannot be linked and run
as-is. This is a pure *read-and-reverse* challenge.

---

## 2. Section layout

```bash
$ readelf -S cow
  [Nr] Name        Type     Address          Offset  Size
  [ 2] .data       PROGBITS 0000000000000000 000178  11   (17 bytes)
  [ 4] .rodata     PROGBITS 0000000000000000 000189  11

$ readelf -S calf
  [ 2] .data       PROGBITS 0000000000000000 000180  10   (16 bytes)
  [ 4] .rodata     PROGBITS 0000000000000000 000190  0d
```

Dumping the meaningful bytes:

```
$ xxd -g1 cow  | sed -n '/00000178/,/00000188/p'
00000178: 39 32 52 4f 67 50 5c 43 55 40 47 7c 5b 49 6d 41  92ROgP\CU@G|[ImA
00000188: 01

$ xxd -g1 calf | sed -n '/00000180/,/00000190/p'
00000180: 36 5e 63 58 52 58 59 72 46 4a 42 40 58 58 6d 01  6^cXRXYrFJB@XXm.
```

* `.rodata` holds "moose noises": `Eurrgh!` for the cow, `eurm...` / `erm` for
  the calf — decoy strings used by a throwaway print method.
* `.data` holds **16 bytes of real ciphertext-ish table** for each object. The
  trailing `0x01` is an **initialized static flag** (`static int already = 1`)
  that the prologue reads and clears.

---

## 3. The prologue — a "first call only" gate

Every function body starts with:

```asm
15: 0f b6 05 00 00 00 00   movzx eax, BYTE PTR [rip+0]   ; static int already
1c: 84 c0                  test  al, al
1e: 74 0e                  je    +0x10                  ; already set -> skip
20: 48 83 7d e0 1f         cmp   QWORD PTR [rbp-0x20],0x1f  ; len == 31 (cow)
25: 74 07                  je    +0x7
27: b8 00 00 00 00         mov   eax, 0
2c: eb 7d                  jmp   ret                     ; return 0
...
31: c6 05 00 00 00 00 00   mov   BYTE PTR [rip+0], 0    ; static int already = 0
```

So the **first** invocation of the function must be with `len == 31` (cow) /
`len == 30` (calf), and afterwards the flag is cleared. This tells us the
top-level call is `cow(input, 31, key)` — an obfuscation that pins the input
length to **31** characters.

---

## 4. Reversing the recursion

Disassembling the main functions (`objdump -d -M intel cow`) gives, in
pseudo-C:

```c
// int cow(char *input, long len, int key)
int cow(char *in, long len, int key) {
    if (static_already && len != 31) return 0;
    static_already = 0;
    if (len == 0) return 1;

    int r = calf(in + 1, len - 1, key + 1);   // call into the OTHER object
    long mid = len >> 1;                      // data index for cow

    if (r && (in[0] ^ key) == cow_data[mid]) return 1;
    return 0;
}

// int calf(char *input, long len, int key)
int calf(char *in, long len, int key) {
    if (static_already && len != 30) return 0;
    static_already = 0;
    if (len == 0) return 1;

    int r = cow(in + 1, len - 1, key + 2);    // call into the OTHER object
    long mid = (len - 1) >> 1;                // data index for calf

    if (r && (in[0] ^ key) == calf_data[mid]) return 1;
    return 0;
}
```

The two critical differences between the objects:

| | cow | calf |
| --- | --- | --- |
| key passed to recursion | `key + 1` | `key + 2` |
| table index | `len >> 1` | `(len-1) >> 1` |
| top-level length | 31 | 30 |

The `movsx eax, al` (sign-extend the low byte) and `mov edx, eax` mean the key
keeps getting incremented down the recursion; at depth `i` the effective key is
the sum of the increments seen so far, plus the initial key.

This is a textbook **mutual recursion** — the "moose family," each member calling
the other until the flag is consumed, character by character.

---

## 5. The math

At depth `i` (0-indexed) the recursion is comparing `flag[i] ^ key_i` against
`table[mid_i]`, where the level alternates cow → calf → cow → … So:

```
level  0  (cow)   : flag[0]  ^ k0        == cow_data[15]
level  1  (calf)  : flag[1]  ^ (k0+1)    == calf_data[14]
level  2  (cow)   : flag[2]  ^ (k0+3)    == cow_data[14]
level  3  (calf)  : flag[3]  ^ (k0+4)    == calf_data[13]
level  4  (cow)   : flag[4]  ^ (k0+6)    == cow_data[13]
...
```

where `k0` is the unknown initial key. We know the flag must begin with
`VuwCTF{`, so:

```
level 0:  'V' ^ k0 == cow_data[15] = 0x41  →  k0 = 'V' ^ 0x41 = 0x17 = 23
level 1:  'u' ^ 24 == calf_data[14] = 0x6d →  0x75 ^ 0x18 = 0x6d ✓
level 2:  'w' ^ 26 == cow_data[14] = 0x6d  →  0x77 ^ 0x1a = 0x6d ✓
level 3:  'C' ^ 27 == calf_data[13] = 0x58 →  0x43 ^ 0x1b = 0x58 ✓
level 4:  'T' ^ 29 == cow_data[13] = 0x49  →  0x54 ^ 0x1d = 0x49 ✓
level 5:  'F' ^ 30 == calf_data[12] = 0x58 →  0x46 ^ 0x1e = 0x58 ✓
level 6:  '{' ^ 32 == cow_data[12] = 0x5b  →  0x7b ^ 0x20 = 0x5b ✓
```

The prefix locks the entry point (`cow`) and the initial key (`23`). The rest of
the flag is obtained by continuing the walk down to length 0:

```python
flag = ""
n, key, cur = 31, 23, "cow"
while n > 0:
    if cur == "cow":
        flag += chr(cow_data[n >> 1] ^ key); key += 1; cur = "calf"
    else:
        flag += chr(calf_data[(n - 1) >> 1] ^ key); key += 2; cur = "cow"
    n -= 1
print(flag)
```

```
VuwCTF{a_family_linked_at_last}
```

The plaintext even comments on the challenge: the cow and calf are a *family,
linked* (mutually recursive) *at last*.

---

## 6. Verifying the flag

To be sure, we emulate the full check (including both prologue gates) on the
recovered string — it passes:

```python
>>> verify("VuwCTF{a_family_linked_at_last}")
True
```

`cow(flag, 31, 23)` and `calf(flag[1:], 30, 24)` both terminate with `True`, so
the flag is structurally correct with respect to the disassembled checks.

---

## 7. Flag

```
VuwCTF{a_family_linked_at_last}
```

### Takeaway

* **Object files are attack surface too.** A stripped `.o` still carries its
  data sections, symbol table, and full code — relocations being zeroed only
  stops *linking*, not *reversing*.
* Flavour text is a cheat-sheet: "objects and C" ⇒ `.o` files, "moose" ⇒ the
  cow/calf family, and the code being two halves of one check is the whole point.
* When a validator is recursive, solve it **depth-first**: fix the entry
  conditions, use a known plaintext prefix to pin any unknown constant, then
  replay the recursion to recover the input.

### References / commands used

- `file`, `strings`, `readelf -a/-S/-r`, `objdump -d -M intel`, `xxd`
- [ELF64 section header layout](https://wiki.osdev.org/ELF)
- [ELF relocations](https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf)
- [Objective-C runtime / `objc_msgSend`](https://developer.apple.com/documentation/objectivec/objective-c_runtime)
