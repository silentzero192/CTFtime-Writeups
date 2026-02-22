#!/usr/bin/env python3

ct = "CA@PC}Wz:~<uR;[_?T;}[XE$%2#|"

# Ensure correct length
assert len(ct) == 28

# Build key: 1→14 then 14→1
key = list(range(1, 15)) + list(range(14, 0, -1))

# XOR decrypt
flag_chars = []
for i in range(28):
    decrypted = ord(ct[i]) ^ key[i]
    flag_chars.append(chr(decrypted))

flag = "".join(flag_chars)

print("Flag:", flag)
