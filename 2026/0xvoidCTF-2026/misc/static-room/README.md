# Static Room — 0xV01D CTF 2026 Writeup

**Category:** `Misc`  
**Difficulty:** `Medium`  
**Challenge Name:** `Static Room`  

---

## Analysis

### Initial Reconnaissance

We're given `06_medium_morse_static.zip`, which contains a single `signal.wav` audio file.

```bash
$ unzip -l 06_medium_morse_static.zip
Archive:  06_medium_morse_static.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   327804  2026-05-17 12:01   signal.wav
```

### WAV File Properties

| Property     | Value          |
|--------------|----------------|
| Channels     | 1 (Mono)       |
| Sample Width | 16-bit signed   |
| Sample Rate  | 8000 Hz        |
| Num Frames   | 163,880        |
| Duration     | 20.48 seconds  |

---

## Signal Analysis

### Step 1: FFT — Finding the Carrier Frequency

A Fast Fourier Transform on the first second of audio reveals the signal is dominated by a single carrier:

```
Top frequencies:
  721.00 Hz (magnitude: 48,366,265)
  720.00 Hz (magnitude: 38,055,355)
  718.00 Hz (magnitude: 37,510,961)
```

The ~720 Hz tone is the signal carrier. The data is modulated in its **amplitude envelope** (AM on-off keying).

### Step 2: RMS Envelope Detection

To extract the on/off pattern, we compute the **Root Mean Square (RMS)** amplitude over sliding windows:

```python
import numpy as np

sr = 8000
window_size = 200  # 25ms per window
rms = []
for i in range(0, len(samples) - window_size, window_size):
    chunk = samples[i:i+window_size]
    r = np.sqrt(np.mean(chunk**2))
    rms.append(r)
```

A threshold of **15,000** separates the tone (ON) from silence/static (OFF):

```python
states = [1 if r > 15000 else 0 for r in rms]
```

### Step 3: Grouping ON/OFF Segments

Consecutive same-state windows are grouped to identify individual morse elements:

| Group Type | Duration    | Windows | Meaning        |
|------------|-------------|---------|----------------|
| ON pulse   | ~50ms       | 2       | **dot** (`.`)  |
| ON pulse   | ~225ms      | 9       | **dash** (`-`) |
| OFF gap    | ~100-125ms  | 4-5     | Intra-element  |
| OFF gap    | ~275-300ms  | 11-12   | **Letter gap** |
| OFF gap    | ~625ms      | 25      | **Word gap**   |

This gives us exactly the standard morse timing ratios:

| Element      | Ratio | Measured  |
|--------------|-------|-----------|
| Dot          | 1     | 50ms      |
| Dash         | 3     | 225ms     |
| Intra-char gap | 1   | 100-125ms |
| Letter gap   | 3     | 275-300ms |
| Word gap     | 7     | 625ms     |

---

## Solution

### Full Extraction Script

```python
import wave
import struct
import numpy as np
from collections import Counter

# --- Read WAV ---
w = wave.open('signal.wav', 'rb')
nframes = w.getnframes()
raw = w.readframes(nframes)
samples = np.array(struct.unpack(f'{nframes}h', raw), dtype=np.float64)
w.close()

# --- RMS envelope detection ---
sr = 8000
window_size = 200  # 25ms
rms = []
for i in range(0, len(samples) - window_size, window_size):
    chunk = samples[i:i+window_size]
    r = np.sqrt(np.mean(chunk**2))
    rms.append(r)

rms_threshold = 15000
states = [1 if r > rms_threshold else 0 for r in rms]

# --- Group ON/OFF ---
groups = []
current = states[0]
count = 1
for s in states[1:]:
    if s == current:
        count += 1
    else:
        groups.append((current, count))
        current = s
        count = 1
groups.append((current, count))

# --- Decode morse ---
morse_chars = []
current_char = ""

for i in range(len(groups)):
    st, cnt = groups[i]
    if st == 1:  # ON pulse
        if cnt <= 4:
            current_char += "."
        else:
            current_char += "-"
    else:  # OFF gap
        if current_char:
            if cnt >= 20:
                morse_chars.append(current_char)
                morse_chars.append("/")
                current_char = ""
            elif cnt >= 10:
                morse_chars.append(current_char)
                current_char = ""

if current_char:
    morse_chars.append(current_char)

print("Morse:", " ".join(morse_chars))

# --- Morse lookup table ---
morse_map = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}

decoded = ""
for c in morse_chars:
    if c == "/":
        decoded += " "
    elif c in morse_map:
        decoded += morse_map[c]
    else:
        decoded += f"[{c}]"

print(f"Decoded: {decoded}")
```

### Decoding Trace

| Morse Code          | Character |
|---------------------|-----------|
| `-----`             | `0`       |
| `-..-`              | `X`       |
| *(word gap)*        |           |
| `...-`              | `V`       |
| `-----`             | `0`       |
| `.----`             | `1`       |
| `-..`               | `D`       |
| *(word gap)*        |           |
| `-- --- .-. ... .`  | `MORSE`   |
| `-- .- -.- . ...`   | `MAKES`   |
| `-. --- .. ... .`   | `NOISE`   |

**Full decoded text:** `0X V01D MORSE MAKES NOISE`

---

## Flag

```
0xV01D{MORSE_MAKES_NOISE}
```
