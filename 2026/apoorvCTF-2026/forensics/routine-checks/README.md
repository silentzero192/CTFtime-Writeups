CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)
Challenge Name: Routine Checks
Platform: aproovCTF (forensics)
Category: Forensics
Difficulty: Medium
Time spent: ~2 hrs

1) Goal (What was the task?)
- The challenge asked me to inspect the provided `challenge.pcap`, determine which communication carried a hidden payload, and extract the real flag of the format `apoorvctf{...}`.

2) Key Clues (What mattered?)
- Prompt referenced “routine checks”, “status updates”, and “one message stands out”.
- Available file `challenge.pcap` contained SIP traffic plus a much larger TCP stream with printable data.
- Strings like `JFIF` and repeated status phrases pointed to embedded media in a TCP stream.

3) Plan (Your first logical approach)
- Start by scanning `challenge.pcap` with `tshark`/`strings` to identify unusual payloads beyond normal SIP status strings.
- Focus on the largest TCP stream, dump its payload, and look for signatures (`JFIF`) indicating hidden media.
- If an image is recovered, brute-force any embedded steganographic data (metadata tools, `steghide`, QR scanners).

4) Steps (Clean execution)
1. `tshark -r challenge.pcap -q -z follow,tcp,ascii,1` → Revealed stream 1 carries a 5.7 KB payload that started with JPEG headers except for one missing `0xFF`.
   - Result: saved payload, prefixed with `0xFF`, produced valid JPEG image.
   - Decision: Image looked like a QR code, so I decoded it with `zbarimg`.
2. `zbarimg /tmp/payload_img.jpg` → Yielded QR code `apoorvctf{this_aint_it_brother}` (decoy flag).
   - Result: confirmed steganographic layers remain; need the true flag hidden deeper.
   - Decision: Inspect image with steghide due to available capacity.
3. `steghide info -p '' /tmp/payload_img.jpg` → Discovered `realflag.txt` embedded, encrypted/compressed.
   - Result: succeeded without passphrase; prompt output revealed compressed/encrypted file name.
   - Decision: Extract with `steghide extract -p ''` and examine contents.
4. `steghide extract -sf /tmp/payload_img.jpg -p '' -xf /tmp/realflag.txt` → Produced file containing `apoorvctf{b1ts_wh1sp3r_1n_th3_l0w3st_b1t}`.
   - Result: This text matches the expected flag format; no further decoding needed.

5) Solution Summary (What worked and why?)
- The key was spotting the non-SIP TCP stream carrying `JFIF` data; saving that stream and fixing the missing JPEG header revealed a QR code decoy, and `steghide` embedded the actual flag inside the image. Accessing `realflag.txt` via the empty password gave the final flag.

6) Flag
- `apoorvctf{b1ts_wh1sp3r_1n_th3_l0w3st_b1t}`

7) Lessons Learned (make it reusable)
- Large TCP streams in mixed traffic captures can hide binary blobs—always inspect the printable payloads for file headers like `JFIF`, `PNG`, or `PK`.
- After recovering media, scan for steganography with `steghide`, `exiftool`, and QR/Barcode decoders before assuming the visible content is the final answer.
- Keep decoy flags (e.g., QR text) and real flags separated; look for additional embedded files or metadata when a suspicious artifact is found.

8) Personal Cheat Sheet (optional, but very useful)
- `tshark -q -z follow,tcp,ascii,<stream>` → reassemble and dump a TCP stream as plain text.
- `zbarimg` / `steghide info/extract` → decode QR codes and uncover files embedded in images.
- `strings` + `rg` → quickly spot unusual keywords (like `JFIF` or status messages) inside large captures.
