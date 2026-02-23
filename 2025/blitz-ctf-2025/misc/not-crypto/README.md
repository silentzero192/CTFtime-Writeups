# CTF Writeup

**Challenge Name:** Not Crypto  
**Platform:** Blitz CTF 2025  
**Category:** Misc  
**Difficulty:** Medium  
**Time Spent:** ~30 minutes  

---

## 1) Goal (What was the task?)

We were given a ZIP file containing:

- `encrypt.cpython-36.pyc`
- `output.txt`

The objective was to recover the flag from the encrypted data provided in `output.txt`.

Success criteria: Retrieve the flag in the format `Blitz{...}`.

---

## 2) Key Clues (What mattered?)

- Category: **Misc**, not Crypto (important hint)
- Description:
  > "It can't be in the crypto category... everything is there for you to grab. Also don't try bruteforcing :>"
- Presence of a `.pyc` file instead of `.py`
- `output.txt` contained:
  - `salt`
  - `nonce`
  - `ciphertext`
  - `tag`
- Suggests AES-GCM encryption with PBKDF2 key derivation
- “Everything is there for you to grab” → password likely hidden somewhere

---

## 3) Plan (Your first logical approach)

- Since a `.pyc` file was provided, inspect it for hidden content.
- Consider steganography or embedded payload.
- Extract any hidden data from the bytecode file.
- Uncompile the `.pyc` file to understand the encryption logic.
- Use recovered password and encryption parameters to decrypt the ciphertext.

---

## 4) Steps (Clean execution)

### Step 1: Inspect Provided Files

```bash
ls
file encrypt.cpython-36.pyc
cat output.txt
```

Confirmed:
- Python 3.6 compiled bytecode file
- JSON containing encryption parameters

---

### Step 2: Extract Hidden Data from `.pyc`

Since it was a compiled file and the challenge hinted that everything was provided, I checked for embedded data using **stegosaurus**:

```bash
./stegosaurus encrypt.cpython-36.pyc -x
```

Output:

```
Extracted payload: whoevenputsthepasswordhereandwhyisitsooooooLONG?
```

This revealed the password.

---

### Step 3: Understand Encryption Method

To understand how encryption was performed, I uncompiled the `.pyc` file using:

```bash
pip install uncompyle6
uncompyle6 encrypt.cpython-36.pyc
```

From the source code, I confirmed:

- Key derivation: **PBKDF2**
- Key length: 32 bytes
- Iterations: 200000
- Encryption mode: **AES-GCM**

---

### Step 4: Write Decryption Script

```python
import base64, json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

password = "whoevenputsthepasswordhereandwhyisitsooooooLONG?"

with open("output.txt") as f:
    data = json.load(f)

salt = base64.b64decode(data["salt"])
nonce = base64.b64decode(data["nonce"])
ciphertext = base64.b64decode(data["ciphertext"])
tag = base64.b64decode(data["tag"])

key = PBKDF2(password.encode(), salt, dkLen=32, count=200000)

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)

print(plaintext.decode())
```

---

### Step 5: Run the Script

```bash
python solver.py
```

Output:

```
Blitz{h0ly_whY_w0uLd_u_puT_tH3_p4ssw0rd_th3re?}
```

---

## 5) Solution Summary (What worked and why?)

This challenge was labeled **Misc**, not Crypto, which was the key hint.

Instead of attacking the encryption directly, the intended approach was:

- Extract the hidden password from the `.pyc` file using steganography.
- Reverse engineer the encryption logic by un-compiling the bytecode.
- Use the extracted password to derive the AES key via PBKDF2.
- Decrypt the ciphertext using AES-GCM with the provided salt, nonce, and tag.

The encryption itself was secure — the weakness was the password being hidden inside the `.pyc` file.

---

## 6) Flag

```
Blitz{h0ly_whY_w0uLd_u_puT_tH3_p4ssw0rd_th3re?}
```

---

## 7) Lessons Learned

- If a challenge is not categorized as Crypto, look for alternative attack vectors.
- `.pyc` files can contain hidden data.
- Steganography tools like `stegosaurus` can extract embedded payloads.
- Always inspect compiled files — sometimes secrets are hidden in plain sight.
- AES-GCM requires correct key, nonce, and tag for successful decryption.

---

## 8) Personal Cheat Sheet

- `file file.pyc` → Identify compiled Python bytecode  
- `stegosaurus file.pyc -x` → Extract hidden payload  
- `uncompyle6 file.pyc` → Reverse engineer Python bytecode  
- ```PBKDF2``` → Derive encryption key from password  
- ```AES-GCM``` → Requires key + nonce + tag  
- `Rule:` If bruteforce is discouraged, the password is probably hidden somewhere  
