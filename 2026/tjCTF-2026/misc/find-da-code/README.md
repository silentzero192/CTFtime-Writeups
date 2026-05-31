# find-da-code

> **CTF:** tjCTF 2026  
> **Category:** Misc  
> **Challenge Name:** find-da-code  
> **Flag:** `tjctf{brut3_f0rc3_th3_t3rm1n4l}`

---

## Challenge Description

> You were assigned 4 unique codes to remember a year ago, but you forgot them! Now you need to figure out a way to get in...
>
> P.S. This challenge was inspired by a particular authentication system I had to bypass because I forgot my pictures lol
>
> `nc tjc.tf 31004`

---

## Initial Analysis

Connecting to the server presents a **4-stage authentication terminal**. Each stage displays 10 hex values, and we must pick one:

```
=== SECURE TERMINAL LOGIN ===

Stage 1
1. 0xBB94
2. 0x22B8
3. 0xC1A7
4. 0x0B74
...
Enter choice for stage 1 (1-10):
```

After all 4 stages, the server checks our selections against a set of "correct tokens." The comparison logic (visible via error messages) is:

```python
if sorted(selected_tokens) == sorted(CORRECT_TOKENS):
    print("ACCESS GRANTED.")
else:
    print("ERROR: Invalid Authentication Sequence.")
```

The `sorted()` comparison means **order doesn't matter** — we just need to pick the right 4 values across the 4 stages.

---

## Key Insight: Fixed "Picture Codes"

The hint about **"forgot my pictures"** is the critical clue. It references authentication systems that use images as backup credentials (like Windows Picture Password). In this challenge, the "pictures" are the **hex values themselves**.

The key observation: **connecting multiple times reveals that 4 specific hex values appear in every session**, while the other 36 are different (random) each time:

| Token | Always Present? |
|-------|-----------------|
| `0x1A2B` | ✅ |
| `0x00FA` | ✅ |
| `0x88D1` | ✅ |
| `0x9C4F` | ✅ |

These 4 values are **generated with a fixed PRNG seed**, making them invariant across connections. The remaining 36 values are randomly generated decoys. The 4 fixed values are the **"4 unique codes"** we were assigned — they never change, we just forgot them.

The "bypass" is simply recognizing that these codes are always the same and can be rediscovered by observing multiple connections.

---

## Solution

### Approach

1. Connect to the terminal  
2. Scan each stage for the 4 known tokens (`0x1A2B`, `0x00FA`, `0x88D1`, `0x9C4F`)  
3. Submit the position of one found token per stage  
4. Receive "ACCESS GRANTED" and the flag

### Solution Code

```python
import socket
import time
import re

CORRECT_TOKENS = [0x1A2B, 0x00FA, 0x88D1, 0x9C4F]

s = socket.socket()
s.settimeout(10)
s.connect(('tjc.tf', 31004))

positions = []
all_data = b''

for stage_idx in range(4):
    buf = b''
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                raise Exception("Connection closed")
            buf += chunk
            if b'Enter choice for stage' in chunk:
                break
        except socket.timeout:
            raise Exception("Timeout waiting for stage data")

    all_data += buf
    text = buf.decode('utf-8', errors='replace')
    vals = [int(v, 16) for v in re.findall(r'0x([0-9A-F]{4})', text)]

    found = False
    for i, val in enumerate(vals):
        if val in CORRECT_TOKENS:
            positions.append(i + 1)
            found = True
            break

    if not found:
        positions.append(1)  # fallback (should never happen)

    s.send(f'{positions[-1]}\n'.encode())
    time.sleep(0.05)

time.sleep(0.5)
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        all_data += chunk
except:
    pass

s.close()
result = all_data.decode('utf-8', errors='replace')
print(result)
```

---

## Flag

```
tjctf{brut3_f0rc3_th3_t3rm1n4l}
```

The flag hints at the solution: **"brute force the terminal"** — in this case, "brute force" means repeatedly connecting until you notice the pattern of fixed values, then using that knowledge to authenticate.
