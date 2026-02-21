# CTF Writeup

**Challenge Name:** Duck's Revenge  
**Platform:** Blitz CTF 2025
**Category:** Misc  
**Difficulty:** Easy  
**Time Spent:** ~15 minutes  

---

## 1) Goal (What was the task?)

We were given a mysterious file named:

```
naknak
```

The challenge description mentioned a “hacker duck” and a USB device, which strongly hinted at a **USB Rubber Ducky** payload.

The objective was to analyze the encoded file and determine what it does in order to recover the flag.

Success criteria: Retrieve the flag in the format `Blitz{...}`.

---

## 2) Key Clues (What mattered?)

- Description mentioned:
  - Hacker duck
  - USB device
- File type:
  ```bash
  file naknak
  ```
  Output:
  ```
  data
  ```
- “Duck” → Strong hint toward **USB Rubber Ducky**
- Rubber Ducky payloads are often encoded in binary format
- Requires decoding to human-readable Ducky Script

---

## 3) Plan (Your first logical approach)

- Since this likely relates to USB Rubber Ducky, use a Ducky payload decoder.
- Decode the binary file to readable Ducky Script.
- Analyze what commands are being executed.
- Follow any URLs or commands found in the decoded output.

---

## 4) Steps (Clean execution)

### Step 1: Identify the File

```bash
ls
file naknak
```

The file type was generic `data`, meaning it required further inspection.

---

### Step 2: Decode Using DuckToolkit

Used the DuckToolkit repository:

🔗 https://github.com/kevthehermit/DuckToolkit

Command used:

```bash
ducktools.py -d -l gb naknak output.txt
```

Output:

```
[+] Reading Duck Bin file
  [-] Decoding file
  [-] Writing ducky text to output.txt
[+] Process Complete
```

---

### Step 3: Analyze Decoded Output

```bash
cat output.txt
```

Output:

```
DELAY
DELAY
https>&&justpaste.it&grp32ENTER
```

This appears to be an obfuscated URL.

Reconstructing it properly:

```
https://justpaste.it/grp32
```

---

### Step 4: Visit the URL

Opening:

```
https://justpaste.it/grp32
```

Revealed the flag.

---

## 5) Solution Summary (What worked and why?)

The challenge relied on recognizing the reference to a **USB Rubber Ducky**.

Key idea:
- Duck → Rubber Ducky payload
- Binary file → Encoded Ducky Script
- Decode using DuckToolkit
- Extract URL from decoded script
- Visit the URL to retrieve the flag

The payload simulated keystrokes to open a webpage containing the flag.

---

## 6) Flag

```
Blitz{1'm_4_nak}
```

---

## 7) Lessons Learned

- Keywords in descriptions often directly hint at the intended tool.
- USB Rubber Ducky payloads can be decoded using DuckToolkit.
- Always inspect decoded scripts for URLs or command execution.
- Encoded keystroke payloads are common in hardware-based CTF challenges.

---

## 8) Personal Cheat Sheet

- Rubber Ducky payload → Use DuckToolkit  
- Decode command:
  ```bash
  ducktools.py -d -l gb file output.txt
  ```
- If output looks like broken URL → Manually reconstruct it  
- Always check for external links in decoded scripts  
- Hardware-themed challenge → Think HID injection  
