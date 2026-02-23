# CTF Writeup

**Challenge Name:** Essay  
**Platform:** Blitz CTF 2025  
**Category:** Forensics  
**Difficulty:** Easy  
**Time Spent:** ~35 minutes  

---

## 1) Goal (What was the task?)

We were given a Microsoft Word macro-enabled document (`Essay.docm`).  
The objective was to analyze the document, understand its embedded OLE/macros behavior, and extract the hidden flag.

Success criteria: Find the flag in the format `Blitz{...}`.

---

## 2) Key Clues (What mattered?)

- File type: `Essay.docm` (macro-enabled Word document)
- Description explicitly mentioned **Object Linking and Embedding (OLE)**
- Suspicious macro functions:
  - `AutoOpen()`
  - `EmbedDesktopZip`
  - `Unscramble`
  - `Chr()` obfuscation
- Obfuscated string: `"zcrseet.ip"` → reversed to `secret.zip`
- Suspicious encoded string:
  ```
  Key & Chr(83) & Chr(117) & Chr(112) ...
  ```
- OLE relationship showed external link (decoy YouTube URL)
- Hint in macro:
  > "The real flag is in the embedded ZIP; Try to extract it If you can :)"

---

## 3) Plan (Your first logical approach)

- Since it’s a `.docm`, extract and analyze macros using **oletools**.
- Deobfuscate suspicious `Chr()` encoded values.
- Inspect for embedded OLE objects or hidden data.
- If macro logic is misleading, directly inspect internal document structure.
- Extract `vbaProject.bin` and search for encoded flag patterns.

---

## 4) Steps (Clean execution)

### Step 1: Identify File Type

```bash
file Essay.docm
```

Confirmed it is a **Microsoft Word 2007+ macro-enabled document**.

---

### Step 2: Extract Macros Using `olevba`

```bash
pip install oletools
py olevba.py Essay.docm > output.txt
```

The macro analysis revealed:

- `AutoOpen()` runs automatically
- Attempts to embed `secret.zip` from Desktop
- Obfuscated filename: `"zcrseet.ip"` → reversed to `secret.zip`
- Suspicious `Chr()` encoded string

---

### Step 3: Decode the Obfuscated Password

Suspicious line:

```
Key & Chr(83) & Chr(117) & Chr(112) & Chr(51) & Chr(114) & ...
```

Decoding ASCII values:

```
Sup3rS3cretPassW0RD
```

However, this turned out to be a **decoy**.

---

### Step 4: Check Embedded OLE Objects

```bash
oleobj Essay.docm
```

Found:

```
Found relationship 'hyperlink' with external link https://www.youtube.com/watch?v=dQw4w9WgXcQ
```

This was also a distraction.

---

### Step 5: Manually Extract DOCM Contents

Since `.docm` files are ZIP archives:

```bash
unzip Essay.docm
```

This extracted internal structure including:

```
word/vbaProject.bin
```

---

### Step 6: Search for Encoded Flag in VBA Binary

Search for Base64 patterns:

```bash
strings vbaProject.bin | grep QmxpdHp7
```

Found:

```
QmxpdHp7MGwzX0QzTXBfTTNsMTBzfQo=
```

---

### Step 7: Decode Base64

Base64:

```
QmxpdHp7MGwzX0QzTXBfTTNsMTBzfQo=
```

Decoding gives:

```
Blitz{0l3_D3Mp_M3l10s}
```

---

## 5) Solution Summary (What worked and why?)

The challenge heavily relied on **misdirection**.

The macros suggested:
- A ZIP file on Desktop
- An obfuscated password
- Embedded OLE behavior
- External links

However, the actual flag was already embedded inside `vbaProject.bin` as a Base64 string.

Key idea:
- `.docm` files are ZIP archives.
- Extract internal files.
- Search for encoded flag patterns.
- Decode Base64 to retrieve the flag.

The macro logic was mostly a distraction.

---

## 6) Flag

```
Blitz{0l3_D3Mp_M3l10s}
```

---

## 7) Lessons Learned

- `.docm` files can be unzipped like regular archives.
- Always inspect `vbaProject.bin` in macro challenges.
- `Chr()` encoding is often used for obfuscation.
- Not all suspicious passwords are real—watch for misdirection.
- Searching for `Base64` flag prefixes (e.g., `QmxpdHp7`) is very effective.

---

## 8) Personal Cheat Sheet

- `olevba file.docm` → Extract and analyze macros  
- `oleobj file.docm` → Extract embedded OLE objects  
- `unzip file.docm` → Extract internal structure  
- `strings file | grep QmxpdHp7` → Search Base64 for `Blitz{`  
- ```Base64 decode``` → `echo "STRING" | base64 -d`  
- ```Rule``` : In macro challenges, always check raw binary for encoded flags  

