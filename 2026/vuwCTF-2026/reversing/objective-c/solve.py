#!/usr/bin/env python3
"""
VuwCTF 2026 - "objective-c" (reversing) solution script

Recovers the flag from the two stripped relocatable ELF object files
`cow` and `calf`.  The methods implement mutual recursion that XORs the
flag with an incrementing key and compares against a byte in the object's
own `.data` section.  We parse the ELF files to pull out `.data`, then
emulate the recursion and brute-force the entry point + initial key.
"""

import struct
import sys
from pathlib import Path


def parse_elf_data(path):
    """Extract the `.data` section bytes from a 64-bit ELF object file."""
    raw = Path(path).read_bytes()

    if raw[:4] != b"\x7fELF":
        raise ValueError(f"{path}: not an ELF file")
    if raw[4] != 2:
        raise ValueError(f"{path}: only ELF64 is supported")

    e_shoff = struct.unpack_from("<Q", raw, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", raw, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", raw, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", raw, 0x3E)[0]

    def sh(idx):
        off = e_shoff + idx * e_shentsize
        return struct.unpack_from("<IIQQQQIIQQ", raw, off)

    # shstrtab is needed to resolve section names
    _, _, _, _, shstr_off, shstr_size, _, _, _, _ = sh(e_shstrndx)
    shstrtab = raw[shstr_off:shstr_off + shstr_size]

    def section_name(sh_name):
        end = shstrtab.index(b"\x00", sh_name)
        return shstrtab[sh_name:end].decode()

    data = None
    for i in range(e_shnum):
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, *_ = sh(i)
        if section_name(sh_name) == ".data":
            data = raw[sh_offset:sh_offset + sh_size]
    if data is None:
        raise ValueError(f"{path}: no .data section found")
    # The last byte is the initialized static "already entered?" flag
    # (the `mov byte [rip+0],0` / `movzx eax,[rip+0]` prologue); the
    # XOR check table is the first 16 bytes.
    return data[:16]


def emulate(cowdata, cldata, entry, key0):
    """
    Walk the mutual recursion exactly like the binaries do.

    cow(len=n): if result of calf(len-1, key+1) is true and
                flag[i] ^ key == cowdata[n >> 1]          -> true
    calf(len=n): if result of cow(len-1, key+2) is true and
                 flag[i] ^ key == cldata[(n-1) >> 1]      -> true
    """
    flag = []
    n = 31 if entry == "cow" else 30
    key = key0
    current = entry
    while n > 0:
        if current == "cow":
            flag.append(chr(cowdata[n >> 1] ^ key))
            key += 1
            current = "calf"
        else:
            flag.append(chr(cldata[(n - 1) >> 1] ^ key))
            key += 2
            current = "cow"
        n -= 1
    return "".join(flag)


def verify(cowdata, cldata, flag):
    """Faithfully emulate the binaries' mutual recursion on the flag."""

    def cow(s, n, key):
        if len(s) == 0:
            return n == 0
        if n <= 0:
            return False
        return calf(s[1:], n - 1, key + 1) and ((s[0] ^ key) == cowdata[n >> 1])

    def calf(s, n, key):
        if len(s) == 0:
            return n == 0
        if n <= 0:
            return False
        return cow(s[1:], n - 1, key + 2) and ((s[0] ^ key) == cldata[(n - 1) >> 1])

    return cow(flag.encode(), 31, 23) and calf(flag.encode()[1:], 30, 24)


def main():
    base = Path(__file__).parent
    cowdata = parse_elf_data(base / "cow")
    cldata = parse_elf_data(base / "calf")

    print(f"[+] cow  .data = {cowdata.hex()}")
    print(f"[+] calf .data = {cldata.hex()}")

    flags = []
    for entry in ("cow", "calf"):
        for key0 in range(256):
            candidate = emulate(cowdata, cldata, entry, key0)
            if candidate.startswith("VuwCTF{") and candidate.endswith("}"):
                flags.append((entry, key0, candidate))

    if not flags:
        sys.exit("[-] no flag-shaped candidate found")

    for entry, key0, flag in flags:
        print(f"[+] entry={entry:<4} initial key={key0:<3} -> {flag}")

    entry, key0, flag = flags[0]
    if verify(cowdata, cldata, flag):
        print(f"[+] flag verified against the check logic")
    else:
        sys.exit("[-] verification failed")
    print(f"\n[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
