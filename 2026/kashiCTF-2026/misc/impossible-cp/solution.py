#!/usr/bin/env python3
import socket
import subprocess
import sys


N = 624
M = 397
MATRIX_A = 0x9908B0DF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF
BIT_MASKS = [1 << bit for bit in range(32)]


def undo_right_xor(value: int, shift: int) -> int:
    result = 0
    for bit in range(31, -1, -1):
        current = (value >> bit) & 1
        if bit + shift <= 31:
            current ^= (result >> (bit + shift)) & 1
        result |= current << bit
    return result


def undo_left_xor_mask(value: int, shift: int, mask: int) -> int:
    result = 0
    for bit in range(32):
        current = (value >> bit) & 1
        if bit - shift >= 0 and ((mask >> bit) & 1):
            current ^= (result >> (bit - shift)) & 1
        result |= current << bit
    return result


def untemper(value: int) -> int:
    value = undo_right_xor(value, 18)
    value = undo_left_xor_mask(value, 15, 0xEFC60000)
    value = undo_left_xor_mask(value, 7, 0x9D2C5680)
    value = undo_right_xor(value, 11)
    return value & 0xFFFFFFFF


class MT19937:
    def __init__(self, state: list[int]):
        self.state = state[:]
        self.index = N

    def twist(self) -> None:
        for i in range(N):
            merged = (self.state[i] & UPPER_MASK) | (self.state[(i + 1) % N] & LOWER_MASK)
            self.state[i] = self.state[(i + M) % N] ^ (merged >> 1)
            if merged & 1:
                self.state[i] ^= MATRIX_A
            self.state[i] &= 0xFFFFFFFF
        self.index = 0

    def next_u32(self) -> int:
        if self.index >= N:
            self.twist()

        value = self.state[self.index]
        self.index += 1

        value ^= value >> 11
        value ^= (value << 7) & 0x9D2C5680
        value ^= (value << 15) & 0xEFC60000
        value ^= value >> 18
        return value & 0xFFFFFFFF


class PipeIO:
    def __init__(self, proc: subprocess.Popen[str]):
        self.proc = proc

    def read_line(self) -> str:
        line = self.proc.stdout.readline()
        if not line:
            stderr = self.proc.stderr.read()
            raise EOFError(f"unexpected EOF from checker, stderr={stderr!r}")
        return line.rstrip("\n")

    def write(self, data: str) -> None:
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def read_rest(self) -> str:
        stdout = self.proc.stdout.read()
        stderr = self.proc.stderr.read()
        return stdout + stderr


class SocketIO:
    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port))
        self.reader = self.sock.makefile("r", encoding="utf-8", newline="\n")
        self.writer = self.sock.makefile("w", encoding="utf-8", newline="\n")

    def read_line(self) -> str:
        line = self.reader.readline()
        if not line:
            raise EOFError("unexpected EOF from remote service")
        return line.rstrip("\n")

    def write(self, data: str) -> None:
        self.writer.write(data)
        self.writer.flush()

    def read_rest(self) -> str:
        chunks = []
        while True:
            data = self.reader.read()
            if not data:
                break
            chunks.append(data)
        return "".join(chunks)


def recover_outputs(io_obj, case_index: int, n: int) -> list[int]:
    query_blob = []
    for i in range(1, N + 1):
        for mask in BIT_MASKS:
            query_blob.append(f"? {i} {mask}\n")
    io_obj.write("".join(query_blob))

    outputs = []
    for i in range(1, N + 1):
        value = 0
        for bit, mask in enumerate(BIT_MASKS):
            response = io_obj.read_line().strip()
            if response not in {"0", "1"}:
                raise ValueError(
                    f"unexpected query response on case {case_index + 1}, index {i}, bit {bit}: {response!r}"
                )
            if response == "1":
                value |= mask
        outputs.append(value)
    return outputs


def predict_last(outputs: list[int], n: int) -> int:
    if n <= N:
        return outputs[n - 1]

    state = [untemper(value) for value in outputs]
    mt = MT19937(state)
    for _ in range(n - N - 1):
        mt.next_u32()
    return mt.next_u32()


def solve(io_obj) -> str:
    t = int(io_obj.read_line().strip())
    for case_index in range(t):
        n = int(io_obj.read_line().strip())
        outputs = recover_outputs(io_obj, case_index, n)
        answer = predict_last(outputs, n)
        io_obj.write(f"! {answer}\n")
    return io_obj.read_rest()


def run_local() -> str:
    proc = subprocess.Popen(
        ["./checker"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=".",
    )
    return solve(PipeIO(proc))


def run_remote() -> str:
    return solve(SocketIO("34.126.223.46", 18607))


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "local"
    if mode == "local":
        result = run_local()
    elif mode == "remote":
        result = run_remote()
    else:
        raise SystemExit(f"usage: {sys.argv[0]} [local|remote]")
    print(result, end="")


if __name__ == "__main__":
    main()
