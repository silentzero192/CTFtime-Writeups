#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path


BASE = 0x400000

FRONT_SBOX1 = 0x4010E0
FRONT_SBOX2 = 0x4011E0
JUMP_TABLE = 0x4010D0
ROUND_WORDS = 0x4013C0
ROUND_BYTES = 0x401460
VM_SBOX1 = 0x4014D0
VM_SBOX2 = 0x4015D0
VM_PROG = 0x4016D0

VM_MASK = 0x402700
FRONT_TARGET = 0x402710
VM_TARGET_LO = 0x402720
VM_TARGET_HI = 0x402730
SUCCESS_CONSTS = 0x4026C0
FLAG_XOR_16 = 0x402740
FLAG_XOR_TAIL_BASE = 0x4026D0

VM_STREAM_SIZE = 0xFC8


def rol32(x: int, r: int) -> int:
    r &= 31
    if r == 0:
        return x & 0xFFFFFFFF
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def ror32(x: int, r: int) -> int:
    r &= 31
    if r == 0:
        return x & 0xFFFFFFFF
    return ((x >> r) | (x << (32 - r))) & 0xFFFFFFFF


def sbox_word(x: int, box: list[int]) -> int:
    return (
        box[x & 0xFF]
        | (box[(x >> 8) & 0xFF] << 8)
        | (box[(x >> 16) & 0xFF] << 16)
        | (box[(x >> 24) & 0xFF] << 24)
    )


def inv_odd_mul(y: int, m: int) -> int:
    mod = 1 << 32
    t, new_t = 0, 1
    r, new_r = mod, m
    while new_r:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if t < 0:
        t += mod
    return (y * t) & 0xFFFFFFFF


class Solver:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.blob = path.read_bytes()

        self.front_sbox1 = list(self.read(FRONT_SBOX1, 256))
        self.front_sbox2 = list(self.read(FRONT_SBOX2, 256))
        self.vm_sbox1 = list(self.read(VM_SBOX1, 256))
        self.vm_sbox2 = list(self.read(VM_SBOX2, 256))
        self.inv_vm_sbox1 = self.make_inverse(self.vm_sbox1)
        self.inv_vm_sbox2 = self.make_inverse(self.vm_sbox2)

        self.round_words = self.read_u32s(ROUND_WORDS, 40)
        self.round_bytes = list(self.read(ROUND_BYTES, 100))
        self.front_target = self.read_u32s(FRONT_TARGET, 4)
        self.vm_target = self.read_u32s(VM_TARGET_LO, 4) + self.read_u32s(VM_TARGET_HI, 4)
        self.success_consts = self.read_u32s(SUCCESS_CONSTS, 4)
        self.flag_xor_16 = self.read(FLAG_XOR_16, 16)
        self.flag_xor_tail = self.read(FLAG_XOR_TAIL_BASE + 0x10, 11)

        self.vm_ops = self.decode_vm()

    def off(self, addr: int) -> int:
        return addr - BASE

    def read(self, addr: int, size: int) -> bytes:
        start = self.off(addr)
        return self.blob[start : start + size]

    def read_u32s(self, addr: int, count: int) -> list[int]:
        return list(struct.unpack(f"<{count}I", self.read(addr, count * 4)))

    @staticmethod
    def make_inverse(box: list[int]) -> list[int]:
        inv = [0] * 256
        for i, v in enumerate(box):
            inv[v] = i
        return inv

    def inv_sbox_word(self, x: int, inv_box: list[int]) -> int:
        return (
            inv_box[x & 0xFF]
            | (inv_box[(x >> 8) & 0xFF] << 8)
            | (inv_box[(x >> 16) & 0xFF] << 16)
            | (inv_box[(x >> 24) & 0xFF] << 24)
        )

    def front_f(self, inp: int, k1: int, k2: int, bs: list[int]) -> int:
        x = sbox_word(rol32(inp ^ k1, bs[0]), self.front_sbox1)
        x = (x + k2) & 0xFFFFFFFF
        y = rol32(k1, bs[2]) ^ x ^ rol32(x, bs[1])
        y = sbox_word(y, self.front_sbox2)
        z = (rol32(k2, bs[3]) + y) & 0xFFFFFFFF
        return rol32(z, bs[4]) ^ z

    def reverse_front(self) -> list[int]:
        state = self.front_target[:]
        for rnd in range(9, -1, -1):
            rw = self.round_words[rnd * 4 : (rnd + 1) * 4]
            rb = self.round_bytes[rnd * 10 : (rnd + 1) * 10]
            a1, b1, c1, d1 = state
            if rnd % 2 == 0:
                c, d, u, v = a1, b1, c1, d1
            else:
                d, c, v, u = a1, b1, c1, d1
            a = u ^ self.front_f(c, rw[0], rw[2], rb[:5])
            b = v ^ self.front_f(d, rw[1], rw[3], rb[5:])
            state = [a, b, c, d]
        return state

    def decode_vm(self) -> list[tuple[str, int, int, int, int]]:
        mapping = [
            "XORR",
            "ADDR",
            "ROL",
            "SBOX1",
            "MIX1",
            "SWAP",
            "XORI",
            "ADDI",
            "MULI",
            "MIX2",
            "SBOX2",
        ]
        mask = self.read(VM_MASK, 8)
        prog = self.read(VM_PROG, VM_STREAM_SIZE)

        ops: list[tuple[str, int, int, int, int]] = []
        w12 = 0x25390348
        w10 = 0x6D2B79F5

        for idx in range(0, len(prog), 8):
            q = prog[idx : idx + 8]
            wb = w12.to_bytes(4, "little")
            b = bytes(q[i] ^ mask[i] ^ wb[i & 3] for i in range(8))
            op = b[0]
            a = b[1] & 7
            c = b[2] & 7
            r = b[3] & 31
            imm = int.from_bytes(b[4:8], "little")
            if op == 0xFF:
                kind = "END"
            elif op == 0:
                kind = "MOVI"
            else:
                if not 1 <= op <= 11:
                    raise ValueError(f"unexpected opcode byte {op:#x} at vm offset {idx:#x}")
                kind = mapping[op - 1]
            ops.append((kind, a, c, r, imm))

            w12 ^= idx & 0xFFFFFFFF
            w0 = imm ^ (op << 24) ^ w12
            w0 = ror32(w0, 25)
            w12 = (w0 + w10) & 0xFFFFFFFF

        return ops

    def reverse_vm(self) -> list[int]:
        regs = self.vm_target[:]
        for idx in range(len(self.vm_ops) - 2, 3, -1):
            kind, a, c, r, imm = self.vm_ops[idx]
            if kind == "XORR":
                regs[a] ^= regs[c]
            elif kind == "ADDR":
                regs[a] = (regs[a] - regs[c]) & 0xFFFFFFFF
            elif kind == "ROL":
                regs[a] = ror32(regs[a], r)
            elif kind == "SBOX1":
                regs[a] = self.inv_sbox_word(regs[a], self.inv_vm_sbox1) ^ imm
            elif kind == "MIX1":
                regs[a] = ((regs[a] - imm) & 0xFFFFFFFF) ^ rol32(regs[c], r)
            elif kind == "SWAP":
                regs[a], regs[c] = regs[c], regs[a]
            elif kind == "XORI":
                regs[a] ^= imm
            elif kind == "ADDI":
                regs[a] = (regs[a] - imm) & 0xFFFFFFFF
            elif kind == "MULI":
                regs[a] = inv_odd_mul(regs[a], imm | 1)
            elif kind == "MIX2":
                regs[a] = (ror32(regs[a] ^ imm, r) - regs[c]) & 0xFFFFFFFF
            elif kind == "SBOX2":
                regs[a] = self.inv_sbox_word(
                    ((regs[a] ^ imm) - rol32(regs[c], r)) & 0xFFFFFFFF,
                    self.inv_vm_sbox2,
                )
            else:
                raise ValueError(f"unexpected VM op {kind!r}")
        return regs[:4]

    def rebuild_flag(self, course_words: list[int]) -> str:
        front_state = self.front_target
        s = [0] * 4
        s[0] = course_words[0] ^ front_state[0] ^ self.success_consts[0]
        s[1] = (course_words[1] + self.success_consts[1] + front_state[1]) & 0xFFFFFFFF
        s[2] = self.vm_target[6] ^ course_words[5] ^ self.success_consts[2]
        s[3] = (self.vm_target[7] + course_words[7] + self.success_consts[3]) & 0xFFFFFFFF

        rot = 7
        for i in range(12):
            idx = i & 3
            x = self.vm_target[(i + 1) & 7] ^ self.success_consts[(i + 2) & 3]
            x ^= front_state[idx] ^ s[idx]
            x = rol32(x, rot)
            rot += 5
            s[idx] = x
            y = sbox_word(x ^ self.success_consts[idx], self.vm_sbox2)
            s[(idx + 1) & 3] = (s[(idx + 1) & 3] + y) & 0xFFFFFFFF

        w3, w2, w7, w6 = s
        x24: list[int] = []
        for i in range(27):
            t = (w3 + w6) & 0xFFFFFFFF
            x24.append(((t >> 24) ^ (t >> 16) ^ (t >> 8) ^ t) & 0xFF)

            t1 = w6 ^ w2
            t4 = w3 ^ w7
            w7 = t4 ^ ((w2 << 9) & 0xFFFFFFFF)
            w2 = t4 ^ w2
            w6 = ror32(t1, 21)
            w3 = ((t1 ^ w3) + self.success_consts[i & 3] + front_state[i & 3]) & 0xFFFFFFFF
            w2 ^= self.vm_target[(i + 2) & 7]

        flag = bytearray(27)
        for i in range(16):
            flag[i] = x24[i] ^ self.flag_xor_16[i]
        for i in range(16, 27):
            flag[i] = x24[i] ^ self.flag_xor_tail[i - 16]
        flag[26] = 0
        return flag[:-1].decode()

    @staticmethod
    def words_to_bytes(words: list[int]) -> bytes:
        return b"".join(struct.pack("<I", w) for w in words)

    def solve(self) -> tuple[str, str]:
        front_words = self.reverse_front()
        tail_words = self.reverse_vm()
        course_words = front_words + tail_words
        course = self.words_to_bytes(course_words).decode()
        flag = self.rebuild_flag(course_words)
        return course, flag


def main() -> None:
    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
    else:
        local = Path("black_ledger")
        sibling = Path(__file__).resolve().with_name("black_ledger")
        path = local if local.exists() else sibling
    solver = Solver(path)
    course, flag = solver.solve()
    print(f"course: {course}")
    print(f"flag:   {flag}")


if __name__ == "__main__":
    main()
