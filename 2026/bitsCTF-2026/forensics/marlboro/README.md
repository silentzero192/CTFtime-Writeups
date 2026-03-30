# CTF Writeup

**Challenge Name:** Marlboro  
**Platform:** BITSCTF  
**Category:** Forensics  
**Difficulty:** Easy  
**Time Spent:** ~20 minutes  

---

## 1) Goal (What was the task?)

We were given a JPEG image (`Marlboro.jpg`) and told that an encrypted transmission was hidden inside it.  
The objective was to recover the flag from the hidden data.  

Success condition: Extract a flag in standard CTF format.

---

## 2) Key Clues (What mattered?)

- Challenge name: **“Marlboro”**
- Description hints:
  - “Where there's smoke, there's fire”
  - “programming language from hell”
- File type: `Marlboro.jpg`
- Hidden embedded files detected inside the image
- Metadata in extracted PNG contained Base64 text
- LSB steganography revealed an XOR key
- Decrypted output contained Malbolge source code

These clues strongly indicated:
- Hidden embedded content inside the image
- A layered approach (steganography + encryption + esoteric language)

---

## 3) Plan (Initial Logical Approach)

- Inspect the JPEG file for embedded data (common in forensics challenges).
- Extract any hidden archives or appended files.
- Analyze extracted files individually (metadata + steganography).
- Use discovered key material to decrypt encrypted content.
- Execute the decrypted code in the appropriate interpreter.

---

## 4) Steps (Clean Execution)

### Step 1 – Inspect the image for embedded data  

**Action:**
```bash
binwalk Marlboro.jpg
```

**Result:**
Binwalk revealed an embedded ZIP archive containing:
- `smoke.png`
- `encrypted.bin`

**Decision:**
Extract the embedded archive.

```bash
binwalk -e Marlboro.jpg
```

---

### Step 2 – Analyze `smoke.png`  

**Action:**
```bash
exiftool smoke.png
```

**Result:**
The `Author` field contained Base64 text:

```
aHR0cHM6Ly96YjMubWUvbWFsYm9sZ2UtdG9vbHMv
```

Decoded:

```bash
echo "aHR0cHM6Ly96YjMubWUvbWFsYm9sZ2UtdG9vbHMv" | base64 -d
```

Output:
```
https://zb3.me/malbolge-tools/
```

This hinted at the esoteric language **Malbolge**.

---

### Step 3 – Run steganography analysis on `smoke.png`

**Action:**
```bash
zsteg smoke.png
```

**Result:**
LSB extraction revealed a 32-byte XOR key in hexadecimal:

```
KEY=c7027f5fdeb20dc7308ad4a6999a8a3e069cb5c8111d56904641cd344593b657
```

It also specified:
> XOR each byte of encrypted.bin with key[i % 32]

**Decision:**
Decrypt `encrypted.bin` using repeating-key XOR.

---

### Step 4 – Decrypt `encrypted.bin`

**Action:**

```python
from itertools import cycle

key_hex = "c7027f5fdeb20dc7308ad4a6999a8a3e069cb5c8111d56904641cd344593b657"
key = bytes.fromhex(key_hex)

with open("encrypted.bin", "rb") as f:
    data = f.read()

decrypted = bytes([b ^ k for b, k in zip(data, cycle(key))])
print(decrypted.decode(errors="ignore"))
```

**Result:**
The decrypted output was clearly Malbolge source code.

It began with:

```
Content-Type: text/x-malbolge
Language: Malbolge
...
```

---

### Step 5 – Execute Malbolge Code

The decrypted source code was pasted into the online interpreter provided in the hint:

https://zb3.me/malbolge-tools/#interpreter

**Result:**
The interpreter immediately printed the flag.

---

## 5) Solution Summary (What worked and why?)

This challenge followed a layered structure:

1. JPEG file contained an embedded ZIP archive.
2. Inside the archive:
   - `smoke.png` hid an XOR key using LSB steganography.
   - `encrypted.bin` contained data encrypted with repeating-key XOR.
3. Decrypting the binary revealed Malbolge source code.
4. Running the Malbolge program printed the flag.

The key pattern behind this solve:
- Steganography → Extract key  
- XOR decryption → Recover code  
- Execute esoteric language → Get flag  

Each layer logically connected through the challenge hints (“smoke”, “fire”, “language from hell”).

---

## 6) Flag

```
BITSCTF{d4mn_y0ur_r34lly_w3n7_7h47_d33p}
```

---

## 7) Lessons Learned

- Always run `binwalk` on image files in forensics challenges.
- PNG images commonly hide data via LSB steganography.
- Repeating-key XOR is a very common CTF encryption technique.
- Esoteric language hints usually mean: run the code in an interpreter, don’t try to manually understand it.

---

## 8) Personal Cheat Sheet

**binwalk** → Detect embedded files in images  
**binwalk -e** → Extract embedded files  
**exiftool** → Inspect metadata (often hides Base64 clues)  
**zsteg** → Extract LSB hidden data from PNG  
**Repeating-key XOR pattern** →  
```
plaintext[i] = ciphertext[i] ^ key[i % key_length]
```
**Esoteric language hint** → Use online interpreter instead of reversing manually  

Pattern reminder:
- Forensics (Images) → Check metadata → Check binwalk → Check LSB → Check appended data  
