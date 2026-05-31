# Sukkar Stash - Writeup

## Challenge

`sukkar-stash` is a static heap challenge with a tiny note service and a hidden command. The included notes deliberately describe an older non-revenge build, so the released binary has to be solved from its real behavior.

Remote flag:

```text
0xV01D{safe_linking_still_needs_a_clean_stash}
```

## Files

- `tcache_stash_revenge`
- `run.sh`

## Protections

```text
Arch: amd64
RELRO: Partial RELRO
Stack: No canary
NX: Enabled
PIE: No PIE
SHSTK: Enabled
IBT: Enabled
```

The static, non-PIE build is the important part:

- Code and global addresses are fixed.
- Glibc internals are baked into the binary.
- Safe-linking is present, so raw tcache poisoning needs a heap-derived mask.

## Menu and data model

The menu is:

```text
1. create
2. edit
3. delete
4. show
5. leave
```

There is also a hidden choice:

```text
1337
```

The binary stores up to `12` slots at `0x4cba60`. Each slot points to a small metadata object:

```c
struct note {
    size_t size;
    char *data;
};
```

## Reversing

### Hidden gate

The hidden function starts at `0x401aa8`:

```asm
mov    rax, qword ptr [0x4cbac0]
cmp    rax, 0x1337
jne    return
...
fopen("flag.txt", "r")
fgets(...)
puts(...)
exit(0)
```

So the goal is simple:

```text
write 0x1337 to 0x4cbac0
then choose 1337
```

### `create`

Relevant behavior:

- Finds the first empty slot in the global slot array.
- Reads a size.
- Requires `0x30 <= size <= 0x100`.
- Allocates `malloc(0x10)` for metadata.
- Allocates `malloc(size)` for data.
- Reads exactly `size` bytes into the data chunk.

### `edit`

This is the key bug:

```asm
slot = get_slot();
new_size = read_int();
slot->size = new_size;
read_exact(slot->data, new_size);
```

Problems:

- It does not reallocate the data buffer.
- It allows editing a freed data pointer because the slot remains valid.
- It updates the stored size even for freed notes.

### `delete`

This is where the bug becomes exploitable:

```asm
slot = get_slot();
free(slot->data);
puts("gone");
```

What it does **not** do:

- it does not free the metadata object
- it does not null the slot entry
- it does not null `slot->data`

So after deletion we still have:

- a valid metadata pointer
- a dangling `data` pointer
- the ability to `show` or `edit` that freed chunk

### `show`

`show` prints:

```asm
puts("data:");
write(1, slot->data, slot->size);
puts("");
```

That gives us a raw leak from freed heap memory.

## Vulnerability summary

The challenge gives us all three pieces we need:

1. UAF read via `show`
2. UAF write via `edit`
3. double free via repeated `delete`

Because the binary is linked against a modern allocator, we cannot just use a stale "no safe-linking" poison. We need a safe-linking aware tcache attack.

## Heap strategy

### Step 1: leak the safe-linking mask

Free a chunk `A` of size `0x40`, then `show` it.

For a singly-freed tcache entry, the first qword is:

```c
PROTECT_PTR(&e->next, NULL) == ((size_t)&e->next >> 12)
```

That leaked value is the exact mask we need for later poisoning.

### Step 2: bypass the tcache double-free check

Modern tcache chunks store:

```c
struct tcache_entry {
    tcache_entry *next;
    uintptr_t key;
}
```

The double-free check relies on `key == tcache_key`. Since `edit` works on freed chunks, we can overwrite the freed chunk and clear the key before calling `delete` again.

That turns:

```text
free(A) -> edit(A_freed) -> free(A)
```

into a working tcache dup primitive.

### Step 3: keep the bin count alive

This challenge is named `tcache_stash_revenge` for a reason: poisoning only the tcache head is not enough.

Why the naive version fails:

- after popping the poisoned chunk, `entries[bin]` may point to the target
- but if `counts[bin] == 0`, malloc ignores that head and falls back to normal allocation

So we keep one legitimate same-sized chunk `B` in the bin:

```text
free(B)
free(A)
```

Now the bin count stays positive after the poisoned pop.

### Step 4: poison `next`

Once we have an alias that still points to freed chunk `A`, we overwrite:

```text
A->next = mask ^ 0x4cbac0
```

Then:

1. one allocation pops `A`
2. tcache head becomes `0x4cbac0`
3. the next allocation of the same size returns a pointer to `0x4cbac0`

### Step 5: write the gate and trigger hidden mode

The final `create` returns `data = 0x4cbac0`, so the note payload writes directly onto the gate:

```python
p64(0x1337).ljust(0x40, b"F")
```

Then we send:

```text
1337
```

and the binary prints the flag.

## Exploit flow

Concrete sequence:

1. `create A`
2. `create B`
3. `delete A`
4. `show A` to leak safe-link mask
5. `edit A` to clear the freed chunk key
6. `delete A` again for tcache dup
7. `create` twice to get two live aliases to the same heap chunk
8. `delete B`
9. `delete one A alias`
10. `edit the other A alias` to poison `next`
11. `create` once to pop poisoned `A`
12. `create` again to allocate directly on `0x4cbac0`
13. send `1337`
