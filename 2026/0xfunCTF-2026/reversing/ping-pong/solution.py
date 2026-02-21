#!/usr/bin/env python3
import binascii

hex_str = "0149545b5f4b5d1e5c545d1a55036c5700404b46505d426e02001b4909030957414a7b7a48"
data = binascii.unhexlify(hex_str)
print("Hex data length:", len(data))
print("Hex data:", data.hex())

# Try common keys
keys = [
    # b"ping",
    # b"pong",
    # b"pingpong",
    # b"pongping",
    # b"0xfun",
    # b"flag",
    # b"0xfun{",
    # b"Now you're pinging the pong!",
    b"112.105.110.103",
    # b"112.111.110.103",
]

for key in keys:
    res = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    if all(32 <= c < 127 or c == 10 for c in res):
        print(f"Key {key}: {res}")
    else:
        # print non-printable as hex
        print(f"Key {key}: {res.hex()}")

# Try XOR with constant from 0 to 255
for k in range(256):
    res = bytes([c ^ k for c in data])
    if all(32 <= c < 127 for c in res):
        print(f"Constant XOR 0x{k:02x}: {res}")

# Try XOR with position
res = bytes([data[i] ^ i for i in range(len(data))])
print("XOR with index:", res)
res = bytes([data[i] ^ (i + 1) for i in range(len(data))])
print("XOR with index+1:", res)

# flag : 0xfun{h0mem4d3_f1rewall_305x908fsdJJ}