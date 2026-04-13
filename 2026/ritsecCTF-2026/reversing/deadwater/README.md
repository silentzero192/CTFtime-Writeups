# Deadwater - Writeup

## Challenge Info

- **Name**: `deadwater`
- **Category**: `reversing`
- **Description**: `The ship's been scuttled, but the strongbox washed ashore. The lock won't let you watch it work.`

## TL;DR

This is a stripped 64-bit PIE ELF that expects one hex-encoded command-line argument.

The program:

1. Requires exactly `80` hex characters.
2. Decodes them into `40` bytes.
3. Builds a large per-position lookup table in memory.
4. Runs the real checker inside Intel TSX transactions (`xbegin`, `xtest`, `xend`, `xabort`), which makes dynamic observation intentionally annoying.
5. Compares the transformed `40` bytes against five hardcoded 64-bit constants.

Instead of fighting the TSX path dynamically, we can emulate the transformation statically and invert it.

Exact hex argv accepted by the checker:

```text
52537b7473785f6465616477617465725f73747233346d5f6369706865725f796172727d00000000
```

---

## Files

- [deadwater](./deadwater)
- [solve.py](./solve.py)

---

## First Look

The binary is small and stripped:

```text
deadwater: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

Useful imported functions immediately stand out:

- `__isoc99_sscanf`
- `strlen`
- `mmap`
- `mprotect`
- `sigaction`
- `write`
- `_exit`

And the strings are very revealing:

```text
narrrr (TSX)
narrrr (abort: 0x%02x)
  [memory conflict detected]
  [explicit abort, code: %d]
  [debug exception inside transaction]
  [transaction capacity exceeded]
nice_try_patches_wont_save_ye_landlubber
walked_the_plank_b4_reaching_port_sarim
99_sailing_ironman_btw_still_narrrr
love_you_using_strings!
yarrr
```

That already suggests:

- Intel TSX is part of the protection.
- There are multiple abort/error cases.
- There is a real success path and a real failure path.

---

## High-Level Control Flow

The important routine starts near `0x1357`.

The program first checks `argc` and the length of `argv[1]`:

```asm
1369: cmp edi,0x2
...
1375: call strlen@plt
137a: cmp rax,0x50
```

So it wants:

- exactly one user argument
- length `0x50 == 80`

If that fails, it prints the generic failure message.

---

## Input Format

The next loop parses the argument two characters at a time using `sscanf("%02x")`:

```asm
13b0: lea rdx,[rsp+0x10]
13b5: mov rax,QWORD PTR [rbp+0x8]
13b9: lea rdi,[rax+rbx*2]
13bd: mov rsi,r12
...
13c5: call __isoc99_sscanf@plt
...
13d7: mov BYTE PTR [rsp+rbx*1+0x40],dl
13db: inc rbx
13de: cmp rbx,0x28
```

So the checker consumes:

```text
80 hex chars -> 40 bytes
```

Those `40` decoded bytes are stored on the stack at `[rsp+0x40]`.

This is why the final working input is a hex string, not the raw flag text.

---

## The Giant Table Generation Phase

After parsing the input, the binary allocates a large RW region:

```asm
13f3: mov ecx,0x22
13f8: mov edx,0x3
13fd: mov esi,0x18000
1407: call mmap@plt
```

Then it generates lookup tables into that region.

The generator runs for `40` outer iterations and `256` inner iterations, which is a strong hint that it is building:

```text
40 positions * 256 entries
```

Each entry is a 64-bit value, and each block is stored at an `0x800` stride:

```asm
14f2: add r14,0x800
```

Since:

```text
256 * 8 bytes = 2048 bytes = 0x800
```

that lines up perfectly.

### What the generator does

The table generation uses:

- a feedback-style recurrence on `rdx`
- a carry bit
- a rotated/shifted sequence based on the outer position
- two evolving accumulators

The important observation is not the thematic complexity, but the structure:

```text
table[position][byte] = deterministic 64-bit value
```

And later, only the low byte of this value is actually used by the checker.

That means once we reproduce the generator statically, we can rebuild the exact same tables in Python.

---

## The TSX-Protected Checker

After the tables are generated, the binary flips the region read-only with `mprotect` and enters two nested TSX transactions:

```asm
155d: xbegin ...
1573: xbegin ...
1582: xtest
1587: xabort 0x41
...
16bb: xend
16be: xend
```

This is the "won't let you watch it work" part of the challenge.

If the transaction aborts, the program prints one of several diagnostic messages:

- memory conflict
- explicit abort
- debug exception inside transaction
- transaction capacity exceeded

On the local machine used here, running the binary directly only produced:

```text
narrrr (TSX)
```

which is consistent with the environment not satisfying the intended TSX path.

So instead of trying to debug inside TSX, the right move is to reimplement the logic statically.

---

## What The Checker Actually Computes

Inside the transaction, the checker processes all `40` decoded bytes.

At a high level, for each byte position `i` it does:

1. Compute a table index from the evolving state.
2. Read a 64-bit value from `table[i][index]`.
3. Keep only its low byte.
4. XOR that byte with the user input byte.
5. Pack the result into one of five 64-bit output words.

The packing is visible here:

```asm
1632: movsxd rsi,eax
1635: mov eax,ecx
1637: xor al,BYTE PTR [rbx+r13*1]
...
1641: shlx rax,rax,rdx
1646: or QWORD PTR [rsp+rsi*8+0x10],rax
```

So each input byte contributes one byte into:

```text
out[0], out[1], out[2], out[3], out[4]
```

with 8 bytes packed into each 64-bit word.

Finally, the checker compares those five words against hardcoded constants:

```asm
16c1: cmp [rsp+0x10], 0xf0c553137025afd6
16dd: cmp [rsp+0x18], 0x376ddfc434d0f4d4
16f1: cmp [rsp+0x20], 0x04f9bde7a77ae197
1705: cmp [rsp+0x28], 0x0a89e4c1254ba31b
171b: cmp rdx,        0xb7c0f25b3f70d12b
```

If all five match, it reaches the success print.

---

## Why Inversion Is Feasible

At first glance the checker state looks messy because several 64-bit values evolve each round.

But the important simplification is:

```text
output_byte[i] = input_byte[i] XOR derived_byte[i]
```

where `derived_byte[i]` depends only on:

- the generated tables
- the evolving internal state

So if we can reproduce `derived_byte[i]`, then:

```text
input_byte[i] = target_byte[i] XOR derived_byte[i]
```

The only missing piece is the initial hidden state entering the transaction.

---

## The Last Unknown: One Byte of State

The checker captures flags with `lahf`, moves them around, and uses that state in the per-byte index logic.

After simplifying the live state, the remaining unknown that matters for inversion is just one byte.

That means we do not need symbolic execution or SMT here.

We can simply:

1. Rebuild the tables.
2. Try all `256` possible initial byte values.
3. Reconstruct the corresponding 40 input bytes.
4. Keep the candidate that looks like a flag.

That is exactly what [solve.py](./solve.py) does.

---

## The Python Inversion

The solver mirrors the binary in two phases.

### 1. Rebuild the lookup tables

`generate_tables()` reimplements the outer/inner generator loop exactly:

- same seed
- same carry handling
- same feedback recurrence
- same rotate distances
- same position-dependent state updates

### 2. Recover the candidate bytes

`recover_candidate()`:

- rebuilds the per-byte derived stream
- XORs it against the target output bytes
- returns the original candidate input bytes

The code then brute-forces the remaining `256` possible initial state bytes and keeps the one that begins with `RS{`.

There is only one sensible hit:

```text
RS{tsx_deadwater_str34m_cipher_yarr}\x00\x00\x00\x00
```

The trailing four NUL bytes are expected because the binary requires a full 40-byte decoded input, and the final four bytes of the accepted payload are zero.

---

## Recovered Values

### Exact hex argv to satisfy the checker

```text
52537b7473785f6465616477617465725f73747233346d5f6369706865725f796172727d00000000
```

That is the exact `80`-character argument expected by the binary.

---

## Validation

Because the local machine aborts in the TSX setup path, the strongest validation here is static:

1. Reconstruct the accepted 40-byte decoded input.
2. Feed it back through the Python reimplementation.
3. Confirm that it reproduces all five hardcoded 64-bit comparison values exactly.

That check succeeded for:

- `0xf0c553137025afd6`
- `0x376ddfc434d0f4d4`
- `0x04f9bde7a77ae197`
- `0x0a89e4c1254ba31b`
- `0xb7c0f25b3f70d12b`

So the recovered input matches the checker precisely.

---

## Why This Challenge Is Nice

This challenge does a good job of combining two different ideas:

- anti-observation / anti-debugging through TSX
- a custom byte-wise stream-style transform hidden behind large-looking state

The TSX layer tries to push solvers toward dynamic frustration, but the underlying check is still deterministic and invertible.

Once the logic is lifted into Python, the problem becomes:

```text
recover input = target XOR derived_stream
```

with only `256` possibilities for the remaining unknown state byte.

So the clean solve is static modeling, not live debugging.

---

## Final Flag

```text
RS{tsx_deadwater_str34m_cipher_yarr}
```
