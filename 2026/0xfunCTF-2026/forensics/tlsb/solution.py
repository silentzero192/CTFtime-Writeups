#!/usr/bin/env python3
# Extract Third Least Significant Bit (TLSB) from 16x16 24-bit BMP

BMP_OFFSET = 54
WIDTH, HEIGHT = 16, 16
BYTES_PER_PIXEL = 3

with open("TLSB", "rb") as f:
    f.seek(BMP_OFFSET)
    data = f.read(WIDTH * HEIGHT * BYTES_PER_PIXEL)

bits = []
for b in data:
    bits.append((b >> 2) & 1)  # bit 2 (third LSB)

# Pack bits, MSB first
flag = bytearray()
for i in range(0, len(bits), 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i + j]
    flag.append(byte)

print(flag.decode("ascii"))
