# Mixed Moose — VuwCTF 2026 (Reversing)

> **Challenge:** Mixed Moose
> **Category:** Reversing
> **Description:** *The moose has been tangled up, please recover it for me :<.*
> **Flag format:** `VuwCTF{...}`

---

## TL;DR

The binary reads a 32-bit hex key, runs it through a function nicknamed
`Meesifier` that transforms the key with a **XOR**, a **rotate-left by 5**, and an
**add** constant, then compares the result to `0x6ADB9A62`. We invert the
transform algebraically to recover the key `0x1FACE`, which is printed as the
flag.

**Flag: `VuwCTF{0x1FACE}`**

---

## Step 1 — Initial Recon

```console
$ file "Mixed Moose"
Mixed Moose: Mach-O 64-bit x86_64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
```

This is a **macOS Mach-O** executable (64-bit x86_64), so GNU `objdump` won't
read it on Linux. We switch to LLVM's tools:

```console
$ llvm-objdump-18 --macho --private-header "Mixed Moose" | head
```

A quick `strings` pass already leaks most of the story:

```
%10x
Correct! VuwCTF{0x%05X}
Meesifier
Enter the key (hex):
Nope.
@___stack_chk_guard
@___stdinp
@___stdoutp
@___stack_chk_fail
@_fflush
@_fgets
@_fputs
@_printf
@_strtoul
```

We learn the program:
1. Prompts for a key in hex.
2. Uses `fgets` to read it and `strtoul` to parse it as base 16.
3. Has a function called `Meesifier` (the "tangled moose").
4. Prints `Correct! VuwCTF{0x%05X}` on success — so the flag is literally
   `VuwCTF{0x` + the input key in hex `}`.

---

## Step 2 — Map the Imported Symbols

Mach-O binaries use a stub table (`__stubs`) that jumps through the lazy
symbol pointer table (`__la_symbol_ptr`). Mapping them tells us which call is
which libc function:

```console
$ llvm-objdump-18 --macho --bind "Mixed Moose"
Bind table:
__DATA_CONST __got   0x100004000  ___stack_chk_guard
__DATA_CONST __got   0x100004008  ___stdinp
__DATA_CONST __got   0x100004010  ___stdoutp

$ llvm-objdump-18 --macho --lazy-bind "Mixed Moose"
Lazy bind table:
__DATA __la_symbol_ptr 0x100008000  ___stack_chk_fail
__DATA __la_symbol_ptr 0x100008008  _fflush
__DATA __la_symbol_ptr 0x100008010  _fgets
__DATA __la_symbol_ptr 0x100008018  _fputs
__DATA __la_symbol_ptr 0x100008020  _printf
__DATA __la_symbol_ptr 0x100008028  _strtoul
```

Stub → function mapping:

| Stub address | Function     |
|--------------|--------------|
| `0x100003ef2` | `___stack_chk_fail` |
| `0x100003ef8` | `_fflush`     |
| `0x100003efe` | `_fgets`      |
| `0x100003f04` | `_fputs`      |
| `0x100003f0a` | `_printf`     |
| `0x100003f10` | `_strtoul`    |

---

## Step 3 — Disassemble `main`

```console
$ llvm-objdump-18 -d "Mixed Moose"
```

Let's walk through `_main` (addresses trimmed for readability):

```asm
_main:
    ; (stack canary setup with ___stack_chk_guard)
    movl    $0x0, -0x54(%rbp)              ; return_value = 0

    ; fputs("Meesifier\n", stdout)
    movq    0x42d4(%rip), %rdi             ; -> "Meesifier\n"
    movq    0x2a5(%rip), %rax              ; -> &___stdoutp
    movq    (%rax), %rsi                   ; -> stdout
    callq   _fputs

    ; fflush(stdout)
    movq    (%rax), %rdi
    callq   _fflush

    ; fgets(buf, 0x40, stdin)
    leaq    -0x50(%rbp), %rdi              ; buf
    movq    0x27b(%rip), %rax              ; -> &___stdinp
    movq    (%rax), %rdx                   ; -> stdin
    movl    $0x40, %esi                    ; size = 64
    callq   _fgets
    cmpq    $0x0, %rax
    jne     .read_ok
    movl    $0x1, -0x54(%rbp)              ; read failed -> exit 1
    jmp     .done

.read_ok:
    ; input = strtoul(buf, NULL, 16)
    leaq    -0x50(%rbp), %rdi              ; buf
    xorl    %eax, %eax
    movl    %eax, %esi                     ; endptr = NULL
    movl    $0x10, %edx                    ; base = 16
    callq   _strtoul
    movl    %eax, -0x58(%rbp)              ; key = (uint32)input

    ; result = Meesifier(key)
    movl    -0x58(%rbp), %edi
    callq   0x100003e60                    ; <Meesifier>
    movl    %eax, -0x5c(%rbp)

    ; printf("%10x\n", result)
    movl    -0x5c(%rbp), %esi
    leaq    0x18a(%rip), %rdi              ; "%10x"
    movb    $0x0, %al
    callq   _printf

    ; if (result == 0x6ADB9A62) ...
    cmpl    $0x6adb9a62, -0x5c(%rbp)
    jne     .nope
    ; printf("Correct! VuwCTF{0x%05X}\n", key)
    movl    -0x58(%rbp), %esi
    leaq    0x171(%rip), %rdi              ; "Correct! VuwCTF{0x%05X}\n"
    callq   _printf
    movl    $0x0, -0x54(%rbp)              ; exit 0
    jmp     .done

.nope:
    ; fputs("Nope.\n", stdout)
    movq    0x422e(%rip), %rdi             ; -> "Nope.\n"
    movq    0x1f7(%rip), %rax
    movq    (%rax), %rsi
    callq   _fputs
    movl    $0x1, -0x54(%rbp)              ; exit 1

.done:
    ; (stack canary check)
    ...
```

### High-level pseudocode

```c
int main(void) {
    char buf[64];
    uint32_t key, result;

    fputs("Meesifier\n", stdout);
    fflush(stdout);

    if (fgets(buf, 64, stdin) == NULL)
        return 1;

    key = (uint32_t)strtoul(buf, NULL, 16);
    result = Meesifier(key);

    printf("%10x\n", result);

    if (result == 0x6ADB9A62) {
        printf("Correct! VuwCTF{0x%05X}\n", key);
        return 0;
    }
    fputs("Nope.\n", stdout);
    return 1;
}
```

The important check: we need to find `key` such that

```
Meesifier(key) == 0x6ADB9A62
```

---

## Step 4 — Understand `Meesifier`

The function at `0x100003e60` is labelled `Meesifier`. It chains three tiny
helpers:

```asm
Meesifier:                     ; uint32_t Meesifier(uint32_t x)
    callq   f1                 ; x = f1(x)
    callq   f2                 ; x = f2(x)
    callq   f3                 ; x = f3(x)
    ret

f1:                            ; x ^ 0x5ABCDEF7
    xorl    $0x5abcdef7, %eax
    ret

f2:                            ; x = (x << 5) | (x >> 27)   == rol32(x, 5)
    shll    $0x5, %eax
    movl    -0x4(%rbp), %ecx   ; original x
    shrl    $0x1b, %ecx        ; >> 27
    orl     %ecx, %eax
    ret

f3:                            ; x + 0x13371337  (32-bit wrap)
    addl    $0x13371337, %eax
    ret
```

So:

```
Meesifier(x) = ((x ^ 0x5ABCDEF7) <<< 5) + 0x13371337   (mod 2^32)
```

where `<<< 5` is a 32-bit left rotate (the high 5 bits wrap around to the
bottom).

---

## Step 5 — Reverse the Transform

We know:

```
((key ^ 0x5ABCDEF7) <<< 5) + 0x13371337 ≡ 0x6ADB9A62   (mod 2^32)
```

Invert step by step (all arithmetic mod `2^32`):

1. Undo the add:

   ```
   y = 0x6ADB9A62 - 0x13371337 = 0x57A4872B
   ```

2. Undo the rotate-left-by-5 (rotation is its own inverse via `>>> 5`):

   ```
   z = ror32(0x57A4872B, 5) = 0x5ABD2439
   ```

3. Undo the xor:

   ```
   key = 0x5ABD2439 ^ 0x5ABCDEF7 = 0x0001FACE
   ```

4. Verify forward:

   ```
   Meesifier(0x0001FACE) = 0x6ADB9A62 ✓
   ```

The key is `0x1FACE`, printed as `VuwCTF{0x%05X}`.

> **Flag: `VuwCTF{0x1FACE}`**

---

## Step 6 — Solve Script

```python
#!/usr/bin/env python3
"""solve.py - Mixed Moose (VuwCTF 2026 reversing challenge)

The binary reads a 32-bit hex key, runs it through "Meesifier":

    Meesifier(x) = ((x ^ 0x5ABCDEF7) <<< 5) + 0x13371337   (mod 2^32)

and prints the flag as `VuwCTF{0x%05X}` with the original key when the
result equals the target 0x6ADB9A62.

This script reverses the transformation algebraically and verifies the
result by running the forward transform.
"""

MASK32 = 0xFFFFFFFF

XOR_KEY = 0x5ABCDEF7
ROTATE_AMOUNT = 5
ADD_KEY = 0x13371337
TARGET = 0x6ADB9A62


def rol32(value: int, amount: int) -> int:
    """Rotate a 32-bit value left by `amount` bits."""
    amount %= 32
    return ((value << amount) | (value >> (32 - amount))) & MASK32


def ror32(value: int, amount: int) -> int:
    """Rotate a 32-bit value right by `amount` bits."""
    amount %= 32
    return ((value >> amount) | (value << (32 - amount))) & MASK32


def meesifier(x: int) -> int:
    """Forward transform extracted from the Meesifier() function."""
    x ^= XOR_KEY
    x = rol32(x, ROTATE_AMOUNT)
    x = (x + ADD_KEY) & MASK32
    return x


def solve() -> int:
    """Invert Meesifier(x) == TARGET to recover x."""
    # 1. Undo the final add.
    y = (TARGET - ADD_KEY) & MASK32
    # 2. Undo the rotate-left-by-5 (same as rotate-right-by-5).
    y = ror32(y, ROTATE_AMOUNT)
    # 3. Undo the xor.
    x = y ^ XOR_KEY
    return x


def main() -> None:
    key = solve()

    # Verify the recovered key satisfies the check.
    assert meesifier(key) == TARGET, "inverse transform failed verification"

    print(f"[*] Meesifier({key:#010x}) == {meesifier(key):#010x}")
    print(f"[*] Flag: VuwCTF{{0x{key:05X}}}")


if __name__ == "__main__":
    main()
```

### Running it

```console
$ python3 solve.py
[*] Meesifier(0x0001face) == 0x6adb9a62
[*] Flag: VuwCTF{0x1FACE}
```

---

## Bonus — Sanity Check Against the Binary

We can't run the Mach-O on Linux, but we can confirm the check by hand with
Python using the exact constants from the disassembly:

```console
$ python3 -c "
M = 0xFFFFFFFF
key = 0x1FACE
x = key ^ 0x5ABCDEF7
x = ((x << 5) | (x >> 27)) & M
x = (x + 0x13371337) & M
print(hex(x))   # 0x6adb9a62 == comparison target
"
0x6adb9a62
```

---

## Key Takeaways

- **Mach-O on Linux:** GNU `binutils` can't parse Mach-O files; use
  `llvm-objdump` (`--macho`, `--bind`, `--lazy-bind`) instead.
- **Stub table mapping:** Always map `__stubs` → `__la_symbol_ptr` → symbol
  name before reading calls; it turns raw `callq` offsets into `fgets`,
  `strtoul`, `printf`, etc.
- **Reversible obfuscation:** A chain of XOR / rotate / add is trivially
  invertible algebraically — no brute force needed.
- **Read the flag format string:** `VuwCTF{0x%05X}` told us exactly what to
  submit before we even solved the math.
