import numpy as np
from PIL import Image

# Read the raw frame
with open("frame.raw", "rb") as f:
    data = f.read()

# Convert to numpy array of uint8
arr = np.frombuffer(data, dtype=np.uint8)

# Reshape to (420005, 5)
samples = arr.reshape(-1, 5)

# The first 5 samples might be a header; try skipping them to get 420000 samples
video_samples = samples[5:]  # shape (420000, 5)

# Reshape to 525 rows, 800 columns
video = video_samples.reshape(525, 800, 5)

# Assume first three channels are R, G, B (adjust if needed)
r = video[:, :, 0]
g = video[:, :, 1]
b = video[:, :, 2]

# Create RGB image
img = np.stack([r, g, b], axis=2).astype(np.uint8)

# Save
Image.fromarray(img).save("vga_frame.png")
print("Saved vga_frame.png")
