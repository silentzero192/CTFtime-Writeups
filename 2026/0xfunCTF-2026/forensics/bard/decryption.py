import struct, zlib

data = open("bits.txt", "rb").read()
decoded = __import__('base64').b64decode(data)

fixed = bytearray(decoded)
fixed[0:8] = b'\x89PNG\r\n\x1a\n'   # Restore PNG signature
fixed[12:16] = b'IHDR'               # Restore IHDR chunk type

# Recalculate IHDR CRC
ihdr_crc = zlib.crc32(fixed[12:29]) & 0xffffffff
struct.pack_into('>I', fixed, 29, ihdr_crc)

open("bits_fixed.png", "wb").write(bytes(fixed))
