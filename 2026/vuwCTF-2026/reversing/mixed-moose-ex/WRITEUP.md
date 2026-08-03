# Mixed Moose EX — vuwCTF 2026

**Category:** Reversing
**Flag:** `VuwCTF{The_0x1FACE_h4s_r3t5ned}`

> The moose has been tangled up again, this time it's in serious trouble, please recover it for me :<.

---

## Table of contents

- [1. Recon](#1-recon)
- [2. Reversing `main`](#2-reversing-main)
- [3. The sidecar loader](#3-the-sidecar-loader)
- [4. The `moose.dat` container format](#4-the-moosedat-container-format)
- [5. The bytecode VM](#5-the-bytecode-vm)
- [6. Recovering the VM programs](#6-recovering-the-vm-programs)
- [7. The two host-side helpers](#7-the-two-host-side-helpers)
- [8. Inverting the mix](#8-inverting-the-mix)
- [9. Solver](#9-solver)
- [10. Flag](#10-flag)
- [11. Notes & takeaways](#11-notes--takeaways)

---

## 1. Recon

Three files ship with the challenge:

```console
$ ls -l
-rw-rw-r-- 1  34368  Mixed Moose EX
-rw-rw-r-- 1 170958  moose.bin
-rw-rw-r-- 1    241  moose.dat

$ file *
Mixed Moose EX: Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
moose.bin:      data
moose.dat:      data
```

An **arm64 Mach-O** — so on a Linux box we're doing this statically. That's fine; the binary is small and unstripped enough to work with.

Strings give away most of the plot:

```
Usage: %s <moose.jpg> <mixed.bin>
moose.dat
%s/moose.dat
could not open moose.dat
moose.dat too small
moose.dat read failed
moose.dat bad magic
vm: bad op 0x%02x at pc=%zu
vm: bad prog id %u
```

Two things jump out:

1. The tool takes a **`moose.jpg`** and produces a **`mixed.bin`**. We were handed the `mixed.bin` (`moose.bin`) and need to run it *backwards*.
2. There is a **virtual machine** (`vm: bad op`, `vm: bad prog id`) whose program lives in `moose.dat`. The real algorithm is data, not code — that's the "EX" twist.

A quick look at `moose.bin`:

```console
$ xxd moose.bin | head -1
00000000: b4f8 c336 16d2 4797 89d7 3670 6291 31d6  ...6..G...6pb.1.

$ xxd moose.bin | tail -1
00029bc0: 30cd 2161 7627 1e28 28a2 8a00 ffd9        0.!av'.((.....
```

The header is garbage, but the file **ends in `FF D9`** — a JPEG EOI marker, in the clear. `170958 = 4 × 42739 + 2`, so the transform almost certainly works on 32-bit words and leaves the trailing 2 bytes untouched. Good early confirmation of the output format and a useful sanity check for later.

Function listing:

```console
$ r2 -q -c "aaa; afl" "Mixed Moose EX"
0x1000004f8   636   main
0x100000774   664   sym.func.100000774     ; load_moose_dat
0x100000a0c   328   sym.func.100000a0c     ; scramble
0x100000b54   184   sym.func.100000b54     ; permute
0x100000c0c  1856   sym.func.100000c0c     ; vm_run   (jump table!)
0x100001450   252   sym.func.100001450     ; prog_lookup
0x10000154c    32   sym.func.10000154c     ; rd32 (unaligned u32 load)
```

Seven functions total. Nothing is obfuscated at the machine-code level — the obfuscation is the interpreter.

---

## 2. Reversing `main`

`main` (`0x1000004f8`) is straightforward:

```c
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "Usage: %s <moose.jpg> <mixed.bin>\n", argv[0]); return 1; }

    load_moose_dat(argv[0]);                    // 0x10000055c

    FILE *f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END); size_t sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 8) { ... }

    uint8_t *buf = calloc(sz + 4, 1);
    fread(buf, 1, sz, f);
    fclose(f);

    uint32_t *w = (uint32_t *)buf;
    size_t    n = sz / 4;                       // 0x10000067c: udiv by 4

    for (size_t i = 0; i < n; i++) {            // 0x10000068c .. 0x1000006f0
        uint32_t j = permute(i, n);             // 0x1000006bc
        w[i] ^= scramble(w[j]);                 // 0x1000006c8 / 0x1000006d8
    }

    FILE *o = fopen(argv[2], "wb");
    fwrite(buf, 1, sz, o);                      // writes sz, not n*4
    fclose(o); free(buf);
    return 0;
}
```

The core loop in assembly, for reference:

```asm
0x1000006a4  ldr  x8, [var_30h]              ; base = buf
0x1000006ac  ldr  x8, [var_sp_20h]           ; i
0x1000006b0  mov  x0, x8                     ; arg0 = i
0x1000006b4  ldr  x8, [var_sp_28h]           ; n
0x1000006b8  mov  x1, x8                     ; arg1 = n
0x1000006bc  bl   sym.func.100000b54         ; j = permute(i, n)
0x1000006c0  ldr  x8, [var_sp_8h]            ; base
0x1000006c4  ldr  w0, [x8, w0, uxtw 2]       ; w[j]
0x1000006c8  bl   sym.func.100000a0c         ; scramble(w[j])
0x1000006cc  ldr  x9, [var_30h]
0x1000006d0  ldr  x10, [var_sp_20h]
0x1000006d4  ldr  w8, [x9, x10, lsl 2]       ; w[i]
0x1000006d8  eor  w8, w8, w0                 ; w[i] ^ scramble(w[j])
0x1000006dc  str  w8, [x9, x10, lsl 2]       ; store back
```

So the whole encoder is:

```
for i = 0 .. n-1:   w[i] ^= scramble( w[ permute(i, n) ] )
```

Note `fwrite` writes `sz` bytes, not `n*4` — that's why the two leftover bytes (`FF D9`) survive verbatim. Also note the loop is **in-place and sequential**, which matters a lot in §8.

---

## 3. The sidecar loader

`load_moose_dat` (`0x100000774`) resolves and slurps the sidecar. It builds a small candidate list and tries each in turn:

1. `"moose.dat"` (CWD)
2. `dirname(argv[0]) + "/moose.dat"` — built with `__snprintf_chk(buf, 0x1000, ..., "%s/moose.dat")`

It `malloc`s the file, `fread`s it, checks `memcmp(buf, "MOOZ", 4)`, and stashes the pointer and length in two globals in `__DATA` at `0x100008000`:

```c
g_dat     = buf;   // 0x100008000
g_dat_len = sz;    // 0x100008008
```

Failure paths all `exit(4)` with the messages we saw in `strings`. Nothing cryptographic here — it's just the loader for the bytecode.

---

## 4. The `moose.dat` container format

`prog_lookup` (`0x100001450`) tells us the layout. It reads a program count from `g_dat + 4`, bounds-checks the requested id against it (`vm: bad prog id %u` → `exit(2)`), then indexes an 8-byte-per-entry table starting at `g_dat + 8`:

```asm
0x100001464  adrp x8, segment.__DATA      ; g_dat
0x10000146c  add  x0, x8, 4               ; &g_dat[4]
0x100001470  bl   sym.func.10000154c      ; count = rd32(g_dat + 4)
...
0x1000014c4  add  x8, x8, 8               ; table = g_dat + 8
0x1000014cc  movz w9, 0x8                 ; stride = 8
0x1000014d4  mul  w9, w9, w10             ; 8 * id
0x1000014e0  bl   sym.func.10000154c      ; off = rd32(&table[id].off)
...
0x100001508  add  x0, x8, 4
0x10000150c  bl   sym.func.10000154c      ; len = rd32(&table[id].len)
...
0x10000153c  add  x0, x8, x9              ; return g_dat + off
```

So:

```c
struct moozhdr {
    char     magic[4];      // "MOOZ"
    uint32_t count;
    struct { uint32_t off, len; } entry[count];
};

const uint8_t *prog_lookup(uint32_t id, uint32_t *out_len);
```

`rd32` (`0x10000154c`) is just an unaligned little-endian `uint32_t` load — the compiler emitted it as its own function because of the packed reads.

Dumping the header of the actual file:

```console
$ xxd moose.dat | head -3
00000000: 4d4f 4f5a 0300 0000 2000 0000 1900 0000  MOOZ.... .......
00000010: 3900 0000 2200 0000 5b00 0000 9600 0000  9..."...[.......
00000020: 1000 0123 00b1 7937 9e28 0007 2300 512d  ...#..y7.(..#.Q-
```

| id | offset | length |
|----|--------|--------|
| 0  | `0x20` | `0x19` (25) |
| 1  | `0x39` | `0x22` (34) |
| 2  | `0x5b` | `0x96` (150) |

`0x5b + 0x96 = 0xf1 = 241` — exactly the file size, so the whole file is accounted for. Three programs, no slack.

---

## 5. The bytecode VM

`vm_run` (`0x100000c0c`) is the interpreter. Signature, from its two call sites:

```c
uint32_t vm_run(uint32_t prog_id, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3);
```

Prologue:

```asm
0x100000c3c  ldur w0, [var_50h]           ; prog_id
0x100000c40  sub  x1, x29, 0x64           ; &code_len
0x100000c44  bl   sym.func.100001450      ; code = prog_lookup(prog_id, &code_len)
0x100000c4c  sub  x0, x29, 0x48
0x100000c50  movz x2, 0x40                ; 64 bytes
0x100000c54  movz w1, 0
0x100000c58  bl   sym.imp.memset          ; memset(regs, 0, 64)   -> 16 x uint32_t
0x100000c5c  ldur w8, [var_54h]
0x100000c60  stur w8, [s]                 ; regs[0] = a0
0x100000c64  ...                          ; regs[1] = a1
0x100000c6c  ...                          ; regs[2] = a2
0x100000c74  ...                          ; regs[3] = a3
0x100000c7c  str  xzr, [var_68h]          ; pc = 0
```

So: **16 × `uint32_t` registers**, zeroed, with the four arguments landing in `r0..r3`. The fetch/dispatch:

```asm
0x100000c84  ldr  x8, [pc]
0x100000c8c  subs x8, x8, code_len
0x100000c90  b.hs 0x100001308             ; pc >= len -> return regs[0]
...
0x100000cac  ldrb w8, [x8]                ; op = code[pc++]
0x100000cc4  subs x8, x8, 0x40
0x100000cc8  b.hi 0x1000012c8             ; op > 0x40 -> "vm: bad op", exit(3)
0x100000cd0  adrp x10, 0x100001000
0x100000cd4  add  x10, x10, 0x34c         ; jump table @ 0x10000134c
0x100000cd8  adr  x8, 0x100000cd8         ; base
0x100000cdc  ldrsw x9, [x10, x11, lsl 2]  ; tbl[op]
0x100000ce0  add  x8, x8, x9
0x100000ce4  br   x8
```

A classic clang jump table: 65 entries (`0x00..0x40`), each a signed 32-bit offset from `0x100000cd8`. Dump it:

```console
$ r2 -q -c "s 0x10000134c; pxw 260" "Mixed Moose EX"
0x10000134c  0x00000010 0x0000001c 0x00000070 0x000005f0
0x10000135c  0x000005f0 0x000005f0 0x000005f0 0x000005f0
...
0x10000138c  0x000000c0 0x0000011c 0x000005f0 0x00000178
0x10000139c  0x000001d4 0x00000230 0x0000028c 0x000002ec
0x1000013ac  0x000005f0 0x000005f0 0x0000034c 0x000005f0
0x1000013cc  0x000005f0 0x000005f0 0x000005f0 0x000003b4
0x1000013ec  0x00000410 0x000005f0 0x000005f0 0x000005f0
0x10000140c  0x000005f0 0x00000494 0x000005f0 0x000005f0
0x10000144c  0x00000524
```

`0x5f0` → `0x1000012c8` is the "bad op" stub, so any entry with that value is an unused opcode. That leaves 15 real instructions, deliberately spread over a sparse encoding space to make guess-the-opcode harder:

| op | offset | handler | operands | semantics |
|----|--------|---------|----------|-----------|
| `0x00` | `0x010` | `0x100000ce8` | — | `return r0` |
| `0x01` | `0x01c` | `0x100000cf4` | `d:u8, imm:u32` | `r[d] = imm` |
| `0x02` | `0x070` | `0x100000d48` | `d:u8, s:u8` | `r[d] = r[s]` |
| `0x10` | `0x0c0` | `0x100000d98` | `d:u8, s:u8` | `r[d] ^= r[s]` |
| `0x11` | `0x11c` | `0x100000df4` | `d:u8, s:u8` | `r[d] += r[s]` |
| `0x13` | `0x178` | `0x100000e50` | `d:u8, s:u8` | `r[d] *= r[s]` |
| `0x14` | `0x1d4` | `0x100000eac` | `d:u8, s:u8` | `r[d] &= r[s]` |
| `0x15` | `0x230` | `0x100000f08` | `d:u8, s:u8` | `r[d] \|= r[s]` |
| `0x16` | `0x28c` | `0x100000f64` | `d:u8, s:u8` | `r[d] <<= (r[s] & 31)` |
| `0x17` | `0x2ec` | `0x100000fc4` | `d:u8, s:u8` | `r[d] >>= (r[s] & 31)` (logical) |
| `0x1a` | `0x34c` | `0x100001024` | `d:u8, k:u8` | `r[d] ^= r[d] >> (k & 31)` |
| `0x23` | `0x3b4` | `0x10000108c` | `d:u8, imm:u32` | `r[d] *= imm` |
| `0x28` | `0x410` | `0x1000010e8` | `d:u8, k:u8` | `r[d] = rotl32(r[d], k & 31)` |
| `0x31` | `0x494` | `0x10000116c` | `a:u8, b:u8, rel:i16` | `if ((u32)r[a] >= (u32)r[b]) pc += rel` |
| `0x40` | `0x524` | `0x1000011fc` | `d:u8, p:u8, a:u8, b:u8, c:u8` | `r[d] = vm_run(p, r[a], r[b], r[c], 0)` |

Two operand-order gotchas worth spelling out, because getting either wrong silently produces garbage:

- For the binary ops the handler reads the **destination byte first**, then the source. E.g. `XOR` at `0x100000d98`: `ldrb [sp,0x5d]` (dst) then `ldrb [sp,0x5c]` (src), and the store goes back to `r[dst]`.
- For `CALL` (`0x1000011fc`) the second operand byte is a **literal program id**, not a register: `ldrb w0, [sp, 0x3a]` feeds `w0` (the `prog_id` argument) directly, while operands 3/4/5 *are* register indices. The callee's 4th argument is hardcoded `0` (`movz w4, 0`), so a callee always sees `r3 = 0`.

`JGE`'s displacement is relative to the pc **after** the 2-byte immediate, and it's signed — so backward jumps (loops) are possible. That detail is the whole trick in prog2.

Execution ends either by `HALT` or by running off the end of the buffer; both return `r0`.

---

## 6. Recovering the VM programs

With the ISA nailed down, a ~100-line Python emulator + disassembler does the rest ([`vm.py`](#vmpy)). Output:

### prog0 — round function (25 bytes)

```
10 00 01                 XOR    r0, r1
23 00 b1 79 37 9e        MULI   r0 *= 0x9e3779b1
28 00 07                 ROTL   r0 <<<= 7
23 00 51 2d 9e cc        MULI   r0 *= 0xcc9e2d51
1a 00 0d                 XORSHR r0 ^= r0 >> 13
14 00 02                 AND    r0, r2
00                       HALT
```

```c
uint32_t prog0(uint32_t x, uint32_t k, uint32_t mask) {
    x ^= k;
    x *= 0x9e3779b1;            // golden-ratio constant
    x  = rotl32(x, 7);
    x *= 0xcc9e2d51;            // murmur3 c1
    x ^= x >> 13;
    return x & mask;
}
```

The constants (`0x9e3779b1`, `0xcc9e2d51`) are recognisable hash-mixer material — a strong hint this is a **Feistel round function**, keyed by `k` and truncated to `mask`.

### prog1 — the inner mixer (34 bytes)

```
01 01 be ba fe ca        LOADI r1, 0xcafebabe
01 02 0f 0f 0f 0f        LOADI r2, 0x0f0f0f0f
01 03 11 00 00 00        LOADI r3, 0x00000011
02 04 00                 MOV   r4, r0
14 04 02                 AND   r4, r2
13 04 03                 MUL   r4, r3
10 00 01                 XOR   r0, r1
11 00 04                 ADD   r0, r4
00                       HALT
```

```c
uint32_t prog1(uint32_t x) {
    return (x ^ 0xcafebabe) + ((x & 0x0f0f0f0f) * 0x11);
}
```

This one is called from the *host* side (see §7), sandwiched in the middle of `scramble`.

### prog2 — 5-round Feistel with cycle walking (150 bytes)

```
02 04 00                 MOV   r4, r0          ; r4 = i >> half   (left)
17 04 01                 SHR   r4, r1
14 04 02                 AND   r4, r2
02 05 00                 MOV   r5, r0          ; r5 = i & mask    (right)
14 05 02                 AND   r5, r2

01 06 fe ca fe ca        LOADI r6, 0xcafecafe  ; --- round 1 ---
40 07 00 05 06 02        CALL  r7 = prog0(r5, r6, r2)
10 04 07                 XOR   r4, r7
02 08 04                 MOV   r8, r4          ; swap(L, R)
02 04 05                 MOV   r4, r5
02 05 08                 MOV   r5, r8

01 06 ef be ad de        LOADI r6, 0xdeadbeef  ; --- round 2 ---
40 07 00 05 06 02        CALL  r7 = prog0(r5, r6, r2)
10 04 07                 XOR   r4, r7
02 08 04 / 02 04 05 / 02 05 08                 ; swap

01 06 37 13 37 13        LOADI r6, 0x13371337  ; --- round 3 ---
   ... same shape ...
01 06 ce fa ed fe        LOADI r6, 0xfeedface  ; --- round 4 ---
   ... same shape ...
01 06 f7 de bc 5a        LOADI r6, 0x5abcdef7  ; --- round 5 ---
   ... same shape ...

16 04 01                 SHL   r4, r1          ; recombine: (L << half) | R
15 04 05                 OR    r4, r5
02 00 04                 MOV   r0, r4
31 00 03 6b ff           JGE   r0 >= r3 -> pc += -149   (back to offset 0)
00                       HALT
```

In C:

```c
uint32_t prog2(uint32_t i, uint32_t half, uint32_t mask, uint32_t n) {
    static const uint32_t rk[5] = {0xcafecafe, 0xdeadbeef, 0x13371337, 0xfeedface, 0x5abcdef7};
    for (;;) {
        uint32_t L = (i >> half) & mask, R = i & mask;
        for (int r = 0; r < 5; r++) {
            uint32_t t = L ^ prog0(R, rk[r], mask);
            L = R; R = t;
        }
        i = (L << half) | R;
        if (i < n) return i;        // JGE loops back while i >= n
    }
}
```

Two nice details:

- It's a **balanced Feistel network** on a `2 × half`-bit block, so it is a bijection on `[0, 2^(2·half))` *regardless* of whether the round function is invertible.
- The backward `JGE` implements **cycle walking**: the Feistel permutes `[0, 65536)`, but we need a permutation of `[0, n)`. Re-encrypting any out-of-range value until it lands in range restricts the permutation to `[0, n)` while staying bijective. This is the standard format-preserving-encryption trick, and it's the reason the challenge can XOR-mix in place without ever colliding two indices.

Note the loop re-derives `L`/`R` from `r0` at the top, so the fall-through into the `JGE` and back to offset 0 is a genuine re-encryption of the current value, not an infinite no-op.

---

## 7. The two host-side helpers

### `scramble` — `0x100000a0c`

A finalizer with `prog1` spliced into the middle:

```c
uint32_t scramble(uint32_t v) {
    v ^= 0x5abcdef7;
    v  = rotl32(v, 5);
    v  = rotl32(v, v >> 27);      // data-dependent rotate
    v ^= v >> 16;
    v *= 0x7feb352d;              // lowbias32 constants
    v ^= v >> 15;
    v  = vm_run(1, v, 0, 0, 0);   // 0x100000ac8  -> prog1
    v *= 0x846ca68b;
    v ^= v >> 13;
    v  = rotr32(v, (v >> 3) & 0x1f);
    v += 0x13371337;
    return v;
}
```

Points where it's easy to slip up while transcribing:

- `0x100000a38`–`0x100000a3c`: `lsr w8, w8, 0x1b` + `orr w8, w8, w9, lsl 5` is `rotl32(v, 5)`, not a shift.
- `0x100000a44`: `s = v >> 27` — the rotate amount is taken from the value's **own top 5 bits**, then applied at `0x100000a58`/`0x100000a74` as `(v << s) | (v >> ((32 - s) & 31))`. The `& 31` matters for `s == 0` (`32 & 31 == 0`, so `v | v == v` — correct).
- `0x100000b10`–`0x100000b28` is the mirrored form (`>> s2` then `<< (32 - s2)`), i.e. a **rotate right**.
- `w10` is reloaded from `[sp]` at `0x100000acc` because the constant `32` was spilled across the `vm_run` call.

It doesn't matter whether `scramble` is invertible — it's only ever used as a keystream generator.

### `permute` — `0x100000b54`

```c
uint32_t permute(uint32_t i, uint32_t n) {
    if (n <= 1) return 0;
    uint32_t bits = 2;
    while ((1ull << bits) < n) bits += 2;     // even bit count -> balanced halves
    uint32_t half = bits / 2;
    uint32_t mask = (1u << half) - 1;
    return vm_run(2, i, half, mask, n);       // 0x100000bf0 -> prog2
}
```

`bits` steps by 2 so the Feistel halves are always equal width. For our file:

```
n = 170958 / 4 = 42739
bits = 16   (2^16 = 65536 >= 42739, 2^14 = 16384 < 42739)
half = 8,  mask = 0xff
```

So we get a 16-bit Feistel cycle-walked down to `[0, 42739)`.

---

## 8. Inverting the mix

Everything now reduces to undoing:

```
for i = 0 .. n-1:   w[i] ^= scramble(w[g(i)])          where g = permute(·, n)
```

The keystream is drawn from the buffer *while the buffer is being modified*, so order is everything. Let `S_i` be the array state **before** step `i`. Step `i` writes exactly one cell:

```
S_{i+1}[i] = S_i[i] ^ scramble(S_i[g(i)])
S_{i+1}[k] = S_i[k]                          for all k != i
```

Run the recovery **backwards**, `i = n-1 → 0`, maintaining the invariant that the array in hand equals `S_{i+1}` when we start step `i`. Then:

```
S_i[i] = S_{i+1}[i] ^ scramble(S_i[g(i)])
```

and since step `i` only touched index `i`, for any `g(i) != i` we have `S_i[g(i)] == S_{i+1}[g(i)]` — a value we already hold. So the inverse is *the identical operation in reverse order*:

```c
for (size_t i = n; i-- > 0; )
    w[i] ^= scramble(w[g[i]]);
```

The one case that would break this is a **fixed point** `g(i) == i`, which would forward-compute `x ^ scramble(x)` and leave us solving for `x`. Worth checking rather than assuming — and it's cheap:

```
permutation? True    fixed points: 0
```

Both properties hold (bijectivity comes free from Feistel + cycle walking; zero fixed points is luck, or more likely the author checked). `g` is deterministic and depends only on `n`, so we precompute it once — 42739 evaluations of a 5-round Feistel, sub-second in Python.

---

## 9. Solver

### `vm.py`

VM emulator + disassembler for the `MOOZ` container.

```python
import struct

dat = open("moose.dat", "rb").read()
assert dat[:4] == b"MOOZ"
nprog = struct.unpack_from("<I", dat, 4)[0]
progs = []
for i in range(nprog):
    off, ln = struct.unpack_from("<II", dat, 8 + 8 * i)
    progs.append(dat[off:off + ln])

M = 0xffffffff

def rotl(v, s):
    s &= 31
    return ((v << s) | (v >> ((32 - s) & 31))) & M if s else v & M

def rotr(v, s):
    s &= 31
    return ((v >> s) | (v << ((32 - s) & 31))) & M if s else v & M

def run(pid, a0=0, a1=0, a2=0, a3=0):
    code = progs[pid]
    r = [0] * 16
    r[0], r[1], r[2], r[3] = a0 & M, a1 & M, a2 & M, a3 & M
    pc = 0
    while pc < len(code):
        op = code[pc]; pc += 1
        if   op == 0x00: return r[0]
        elif op == 0x01:
            d = code[pc]; r[d] = struct.unpack_from("<I", code, pc + 1)[0]; pc += 5
        elif op == 0x02: d, s = code[pc:pc+2]; pc += 2; r[d]  = r[s]
        elif op == 0x10: d, s = code[pc:pc+2]; pc += 2; r[d] ^= r[s]
        elif op == 0x11: d, s = code[pc:pc+2]; pc += 2; r[d]  = (r[d] + r[s]) & M
        elif op == 0x13: d, s = code[pc:pc+2]; pc += 2; r[d]  = (r[d] * r[s]) & M
        elif op == 0x14: d, s = code[pc:pc+2]; pc += 2; r[d] &= r[s]
        elif op == 0x15: d, s = code[pc:pc+2]; pc += 2; r[d] |= r[s]
        elif op == 0x16: d, s = code[pc:pc+2]; pc += 2; r[d]  = (r[d] << (r[s] & 31)) & M
        elif op == 0x17: d, s = code[pc:pc+2]; pc += 2; r[d]  = r[d] >> (r[s] & 31)
        elif op == 0x1a: d, k = code[pc:pc+2]; pc += 2; r[d] ^= r[d] >> (k & 31)
        elif op == 0x23:
            d = code[pc]; imm = struct.unpack_from("<I", code, pc + 1)[0]; pc += 5
            r[d] = (r[d] * imm) & M
        elif op == 0x28: d, k = code[pc:pc+2]; pc += 2; r[d] = rotl(r[d], k)
        elif op == 0x31:
            a, b = code[pc:pc+2]
            rel = struct.unpack_from("<h", code, pc + 2)[0]; pc += 4
            if r[a] >= r[b]: pc += rel
        elif op == 0x40:
            d, p, a, b, c = code[pc:pc+5]; pc += 5
            r[d] = run(p, r[a], r[b], r[c], 0)
        else:
            raise Exception(f"bad op {op:02x} at pc={pc-1}")
    raise Exception("fell off end")
```

(The full file also carries a `disasm()` that produced the listings in §6.)

### `solve.py`

```python
import struct
from vm import run, rotl, rotr, M

def scramble(x):                       # 0x100000a0c
    v = x & M
    v ^= 0x5abcdef7
    v  = rotl(v, 5)
    v  = rotl(v, v >> 27)
    v ^= v >> 16
    v  = (v * 0x7feb352d) & M
    v ^= v >> 15
    v  = run(1, v, 0, 0, 0)            # prog1
    v  = (v * 0x846ca68b) & M
    v ^= v >> 13
    v  = rotr(v, (v >> 3) & 0x1f)
    v  = (v + 0x13371337) & M
    return v

def permute(i, n):                     # 0x100000b54
    if n <= 1:
        return 0
    bits = 2
    while (1 << bits) < n:
        bits += 2
    half = bits // 2
    return run(2, i, half, (1 << half) - 1, n)   # prog2

raw = bytearray(open("moose.bin", "rb").read())
n = len(raw) // 4
data = list(struct.unpack_from("<%dI" % n, raw, 0))

g = [permute(i, n) for i in range(n)]
assert len(set(g)) == n,                  "g is not a permutation"
assert not any(g[i] == i for i in range(n)), "fixed point -> not invertible"

for i in range(n - 1, -1, -1):            # reverse order is the whole trick
    data[i] ^= scramble(data[g[i]])
    data[i] &= M

struct.pack_into("<%dI" % n, raw, 0, *data)
open("recovered.jpg", "wb").write(raw)
print("magic:", raw[:4].hex())
```

Run:

```console
$ python3 solve.py
prog0: off=0x20 len=0x19
prog1: off=0x39 len=0x22
prog2: off=0x5b len=0x96
len 170958 words 42739
permutation? True fixed points: 0
magic: ffd8ffe0 tail: 40ffffd9

$ file recovered.jpg
recovered.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI),
density 300x300, segment length 16, baseline, precision 8, 1949x1285, components 3
```

`FF D8 FF E0` at the front, `FF D9` still at the back — a clean JPEG.

---

## 10. Flag

The recovered image is a moose with the flag watermarked diagonally across it. Rotating by ~31.5° makes it legible:

```python
from PIL import Image
Image.open("recovered.jpg").rotate(-31.5, expand=True, resample=Image.BICUBIC).save("rot.png")
```

![recovered moose](recovered.jpg)

```
VuwCTF{The_0x1FACE_h4s_r3t5ned}
```

---

## 11. Notes & takeaways

**Why this is harder than a normal crackme.** Nothing in the Mach-O is obfuscated — the difficulty is that the algorithm isn't in the binary at all. `Mixed Moose EX` is a generic 15-opcode interpreter; `moose.dat` is the payload. You cannot understand the transform by reading the disassembly alone, and you cannot understand `moose.dat` without first recovering the ISA. That split is the challenge.

**The sparse opcode map is deliberate.** Live opcodes are `00 01 02 10 11 13 14 15 16 17 1a 23 28 31 40` — 15 out of 65 slots, with gaps (`0x12` missing between `ADD` and `MUL`). Guessing the encoding from the bytecode alone is impractical; you have to read the jump table at `0x10000134c` and resolve each entry against the `adr` base at `0x100000cd8`.

**The single backward `JGE` carries a lot of weight.** It's one instruction, but it turns a fixed-domain Feistel into a format-preserving permutation of `[0, n)` for an arbitrary `n`. Miss the sign on the `i16` displacement and prog2 looks like a plain Feistel that returns out-of-range indices, and every derived index is wrong.

**Recognise your constants.** `0x9e3779b1` (golden ratio), `0xcc9e2d51` (murmur3), `0x7feb352d` / `0x846ca68b` (`lowbias32`) all showed up. They don't decide anything on their own, but seeing them in prog0 said "hash-style round function" immediately, which framed prog2 as a Feistel before the structure was fully decoded.

**Think about *when* the state is read, not just what.** The mix is `w[i] ^= scramble(w[g(i)])` in place, so a naive "just XOR it again" pass forward produces garbage. The inverse is byte-identical arithmetic run in reverse index order — and it's only valid because step `i` writes a single cell and `g` has no fixed points. Both facts are worth *checking* (two asserts) rather than assuming.

**Free oracles are worth noticing early.** The trailing `FF D9` was visible in the untouched tail from the very first hexdump, which confirmed both the output file type and that the transform is word-granular with a 2-byte remainder — before any real reversing happened. And `FF D8 FF E0` appearing at offset 0 after the reverse pass is an instant, unambiguous "the whole chain is correct".

---

## Artifacts

| file | description |
|------|-------------|
| `Mixed Moose EX` | arm64 Mach-O host + VM interpreter |
| `moose.dat` | `MOOZ` container, 3 bytecode programs |
| `moose.bin` | mixed JPEG (challenge input) |
| `vm.py` | VM emulator + disassembler |
| `solve.py` | inverse-mix solver |
| `recovered.jpg` | recovered image containing the flag |
