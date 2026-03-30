from PIL import Image
import numpy as np

img = Image.open("bit_45.png").convert("L")  # grayscale
pixels = np.array(img)

# Invert if text is white on black (0 = black, 255 = white)
# Usually flag text is black on white, so we threshold and invert
binary = (pixels < 128).astype(int)  # 1 for black pixels

# Define region (adjust based on visual inspection)
y_start, y_end = 200, 300
x_start, x_end = 200, 400

for y in range(y_start, y_end):
    line = "".join("#" if binary[y, x] else " " for x in range(x_start, x_end))
    print(line)
