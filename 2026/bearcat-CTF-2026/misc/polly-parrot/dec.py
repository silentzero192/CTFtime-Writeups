import wave
import numpy as np
import matplotlib.pyplot as plt
from scipy import signal as sig

# Read the WAV file
wf = wave.open('polly_recording.wav', 'rb')
framerate = wf.getframerate()
n_frames = wf.getnframes()
audio = np.frombuffer(wf.readframes(n_frames), dtype=np.int16)
wf.close()

# If stereo, take one channel (or average)
if len(audio.shape) > 1:
    audio = audio[:, 0]  # use first channel

# Generate spectrogram with high contrast
plt.figure(figsize=(12, 6))
f, t, Sxx = sig.spectrogram(audio, fs=framerate, nperseg=2048, noverlap=1536)
plt.pcolormesh(t, f, 10 * np.log10(Sxx + 1e-10), cmap='gray', shading='gouraud')
plt.axis('off')
plt.tight_layout(pad=0)
plt.savefig('spectrogram_enhanced.png', dpi=300, bbox_inches='tight', pad_inches=0)
plt.close()
