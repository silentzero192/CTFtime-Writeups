# Secret Word Writeup

Challenge Name: Secret Word  
Platform: Texsaw CTF 2026  
Category: Forensics  
Difficulty: Easy  
Time spent: 5 minutes

## 1) Goal (What was the task?)
We were given a suspicious Word document and told that the flag was hidden somewhere inside it. Success meant extracting a value in the format `texsaw{...}`.

## 2) Key Clues (What mattered?)
- The description said the flag was hidden in a suspicious Word document.
- The file provided was `challenge.docx`.
- `.docx` files are actually ZIP archives that contain XML, media, and metadata files.
- The archive contained an unusual extra file named `secret.txt` at the top level.
- The contents of `secret.txt` looked like base64.

## 3) Plan (Your first logical approach)
- Check the file type first to confirm what kind of document we are dealing with.
- Inspect the internal ZIP structure of the `.docx` instead of opening it in Microsoft Word.
- Look for anything unusual such as extra files, metadata, embedded objects, or encoded text.
- Extract suspicious content and decode it if needed.

## 4) Steps (Clean execution)
1. Action: Ran `file challenge.docx` to confirm the file type.  
   Result: It was identified as a Microsoft Word 2007+ document.  
   Decision: Since modern Word documents use the OOXML format, I treated it as a ZIP archive.

2. Action: Listed the archive contents with `unzip -l challenge.docx`.  
   Result: Most files were normal Word internals like `word/document.xml`, images, and metadata files. One entry stood out: `secret.txt`.  
   Decision: A top-level `secret.txt` is not standard in a normal Word document, so that became the main lead.

3. Action: Extracted the hidden file with `unzip -p challenge.docx secret.txt`.  
   Result: The output was `dGV4c2F3e3N1cnByMXNlIV93MHJkX2YxbGVzX2FyM196MXBfNHJjaGl2ZXNfNjA3MDkwMTM3NzF9`.  
   Decision: The string matched the pattern of base64-encoded text, so the next step was decoding it.

4. Action: Decoded the base64 string with `unzip -p challenge.docx secret.txt | base64 -d`.  
   Result: The decoded text was `texsaw{surpr1se!_w0rd_f1les_ar3_z1p_4rchives_60709013771}`.  
   Decision: That matched the expected flag format, so the challenge was solved.

## 5) Solution Summary (What worked and why?)
The key idea was recognizing that a `.docx` file is really a ZIP archive. Instead of wasting time reading the huge XML document first, I checked the archive contents and immediately found an unusual file called `secret.txt`. That file contained a base64-encoded string, and decoding it revealed the flag. The challenge was testing whether the player knew to inspect Office documents as archives during basic forensics work.

## 6) Flag
`texsaw{surpr1se!_w0rd_f1les_ar3_z1p_4rchives_60709013771}`

## 7) Lessons Learned (make it reusable)
- Modern Office files like `.docx`, `.xlsx`, and `.pptx` should always be treated as ZIP archives during forensics challenges.
- When a challenge says a document is suspicious, check for unusual embedded files before diving into the main content.
- Encoded strings inside hidden files are often base64, hex, or compressed data, so try simple decoding steps early.
- A quick archive listing can save a lot of time compared to manually reviewing large XML files.

## 8) Personal Cheat Sheet (optional, but very useful)
- `file <filename>` -> quickly identify what kind of file you are dealing with
- `unzip -l <file.docx>` -> list the internal files inside an Office document
- `unzip -p <file.docx> <internal-file>` -> print a file from inside the archive without extracting everything
- `base64 -d` -> decode base64 text
- Pattern: Office documents -> check internal ZIP contents early
