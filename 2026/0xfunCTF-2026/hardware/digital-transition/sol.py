from PIL import Image
import struct

def tmds_decode(symbol_10bit):
    """Decode a 10-bit TMDS symbol to 8-bit data value."""
    bit9 = (symbol_10bit >> 9) & 1  # inversion flag
    bit8 = (symbol_10bit >> 8) & 1  # XOR/XNOR mode flag
    qm = symbol_10bit & 0xFF
    if bit9:
        qm = qm ^ 0xFF
    d = [0] * 8
    d[0] = qm & 1
    for i in range(1, 8):
        if bit8:  # XOR mode
            d[i] = ((qm >> i) & 1) ^ ((qm >> (i-1)) & 1)
        else:     # XNOR mode
            d[i] = ((qm >> i) & 1) ^ ((qm >> (i-1)) & 1) ^ 1
    result = 0
    for i in range(8):
        result |= (d[i] << i)
    return result

data = open('signal.bin', 'rb').read()
data = data[16:]  # skip "check end." header

width, height = 800, 525
img = Image.new('RGB', (width, height))
pixels = img.load()

for y in range(height):
    for x in range(width):
        offset = (y * width + x) * 4
        if offset + 3 >= len(data):
            break
        word = struct.unpack_from('<I', data, offset)[0]
        ch0 = word & 0x3FF          # Blue  (bits 9:0)
        ch1 = (word >> 10) & 0x3FF  # Green (bits 19:10)
        ch2 = (word >> 20) & 0x3FF  # Red   (bits 29:20)
        blue = tmds_decode(ch0)
        green = tmds_decode(ch1)
        red = tmds_decode(ch2)
        pixels[x, y] = (red, green, blue)

# Crop to active video area (skip blanking)
active = img.crop((0, 35, 640, 515))
active.save('output.png')
