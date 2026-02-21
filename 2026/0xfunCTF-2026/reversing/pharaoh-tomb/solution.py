#!/usr/bin/env python3
import struct
import subprocess
import os

binary = "tomb_guardian"
archive = "sacred_chamber.7z"

# Offsets from objdump: .data at file offset 0x3000, VMA 0x4000
base_vma = 0x4000
base_offset = 0x3000


def vma_to_offset(vma):
    return vma - base_vma + base_offset


dword_addr = 0x4020
byte_addr = 0x4040

with open(binary, "rb") as f:
    data = f.read()

dword_off = vma_to_offset(dword_addr)
byte_off = vma_to_offset(byte_addr)

length = struct.unpack("<I", data[dword_off : dword_off + 4])[0]
print(f"[+] Bytecode length: {length}")

bytecode = data[byte_off : byte_off + length]
print(f"[+] Bytecode (hex): {bytecode.hex()}")
try:
    ascii_str = bytecode.decode("ascii")
    print(f"[+] As ASCII: {ascii_str}")
except:
    ascii_str = None

# Try the ASCII string if printable
if ascii_str and all(32 <= ord(c) < 127 for c in ascii_str):
    password = ascii_str
else:
    # Otherwise use the hex representation
    password = bytecode.hex()

print(f"[+] Trying password: {password}")

cmd = ["7z", "x", archive, f"-p{password}", "-y"]
result = subprocess.run(cmd, capture_output=True, text=True)
if result.returncode == 0:
    print("[+] Extraction successful!")
    # Look for the flag file
    for root, dirs, files in os.walk("."):
        for f in files:
            if "flag" in f or "sacred" in f:
                with open(os.path.join(root, f), "r") as ff:
                    print(ff.read())
else:
    print("[-] Wrong password. Trying raw bytes as latin1 string...")
    password = bytecode.decode("latin1")
    cmd = ["7z", "x", archive, f"-p{password}", "-y"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("[+] Extraction successful with latin1!")
        # Look for flag
        for root, dirs, files in os.walk("."):
            for f in files:
                if "flag" in f or "sacred" in f:
                    with open(os.path.join(root, f), "r") as ff:
                        print(ff.read())
    else:
        print("[-] Failed. The bytecode itself might be the flag?")
        print("Try submitting the hex string as flag: 0xfun{" + bytecode.hex() + "}")
