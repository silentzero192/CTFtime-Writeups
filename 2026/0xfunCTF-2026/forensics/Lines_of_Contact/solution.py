import numpy as np
from scipy.io import wavfile
from scipy.signal import find_peaks
from PIL import Image

rate, data = wavfile.read('record.wav')
data = data.astype(float)

# Find sync pulses (sharp negative spikes)
peaks, _ = find_peaks(-data, height=25000, distance=200)

# Extract scan lines between consecutive pulses
width = 384
lines = []
for i in range(len(peaks) - 1):
    start = peaks[i] + 5
    end = peaks[i + 1] - 5
    line = data[start:end]
    if len(line) > 500 or len(line) < 10:
        continue
    indices = np.linspace(0, len(line) - 1, width).astype(int)
    lines.append(line[indices])

img_data = np.array(lines)
img_data = ((img_data - img_data.min()) / (img_data.max() - img_data.min()) * 255).astype(np.uint8)
Image.fromarray(img_data).save('decoded.png')
