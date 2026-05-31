#!/usr/bin/python3
import time

def main():
    key = input("Enter the key: ")

    if (not key.isalnum()) or (len(key) % 3):
        return 1

    part1 = part2 = part3 = ""

    for i in range(0, len(key), 3):
        part1 += key[i]
        part2 += key[i+2]
        part3 += key[i+1]

    if not (len(part1) >= 8):
        return 1

    target1 = "\x08?'!#!\x1b7"

    for i, keypair in enumerate(zip(part1, "GibsonIs")):
        if chr(ord(keypair[0])^ord(keypair[1])) != target1[i]:
            return 1

    target2 = (int(time.time()) >> 2).to_bytes(8, "little")

    for keypair in zip(part2, target2):
        if chr((keypair[1] % 26) + 0x61) != keypair[0]:
            return 1

    for i, keypair in enumerate(zip(part1, part2)):
        if chr(((ord(keypair[0]) +ord(keypair[1]) )% 26) + 0x61) != part3[i]:
            return 1

    return 0

if __name__ == "__main__":
    if not main():
        print(f"FLAG: {open('/flag.txt').read()}")


