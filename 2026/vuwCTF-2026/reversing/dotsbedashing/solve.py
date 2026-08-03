#!/usr/bin/env python3
"""
Solver for the "dotsbedashing" reversing challenge (VuwCTF 2026).

Reverse engineered checker (see WRITEUP.md for details):

  g = 0xb1e1e1f1              # global, rotates right by 1 every character
  for each char c (and 4-byte entry enc[i] of the table at 0x40c0):
      g  = ror(g, 1)
      idx = func_147c(c)      # find table entry (0x4020) whose char == c
      tmp = enc[i] ^ g        # tmp holds the morse pattern for this position
      ok  = func_15ac(tmp, idx)   # compares morse strings

  Each 4-byte morse entry encodes:
      byte0 (v & 0xff)        : bit pattern, 1 = dash, 0 = dot
      byte1 ((v>>8) & 0xff)   : number of morse symbols (length)
      byte2 ((v>>16)&0xff)    : the letter (rotated, see below)
      byte3 ((v>>24)&0xff)    : rotation amount for byte2

  func_147c / func_14f8:  char = rol(byte2, byte3 mod 8)
  func_1637: builds the morse string (length byte1, bits from byte0) but a
             bug (`cmp eax, -45` instead of `cmp eax, 0`) makes every symbol
             identical, so only the length is really compared.

  The encrypted transmission (0x40c0) decodes, after XOR with the rotating
  g, to the morse word-by-word message, with the morse digit 0 (-----) used
  as a word separator.
"""

import struct

BIN = "dotsbedashing"

MORSE = {
    "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.",
    "g": "--.", "h": "....", "i": "..", "j": ".---", "k": "-.-", "l": ".-..",
    "m": "--", "n": "-.", "o": "---", "p": ".--.", "q": "--.-", "r": ".-.",
    "s": "...", "t": "-", "u": "..-", "v": "...-", "w": ".--", "x": "-..-",
    "y": "-.--", "z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
}
MORSE_INV = {v: k for k, v in MORSE.items()}

MASK32 = 0xFFFFFFFF


def ror(v: int, n: int) -> int:
    n %= 32
    return ((v >> n) | (v << (32 - n))) & MASK32


def load_u32(addr: int, data: bytes, base: int) -> int:
    off = addr - base
    return struct.unpack("<I", data[off:off + 4])[0]


def main() -> None:
    with open(BIN, "rb") as f:
        f.seek(0x3000)                      # .data file offset for vaddr 0x4000
        section = f.read(0x110)

    g = load_u32(0x40B0, section, 0x4000)
    enc = [load_u32(0x40C0 + 4 * i, section, 0x4000) for i in range(18)]

    message = ""
    for i, e in enumerate(enc):
        g = ror(g, 1)
        t = e ^ g
        bits = t & 0xFF                     # 1 = dash, 0 = dot
        cnt = (t >> 8) & 0xFF               # morse symbol count
        morse = "".join(
            "-" if (bits >> k) & 1 else "." for k in range(cnt - 1, -1, -1)
        )
        message += MORSE_INV.get(morse, "?")

    flag = f"VuwCTF{{{message}}}"
    print(f"[*] morse transmission : {message}")
    print(f"[*] decoded message    : {message.replace('0', ' ')}")
    print(f"[+] FLAG               : {flag}")


if __name__ == "__main__":
    main()
