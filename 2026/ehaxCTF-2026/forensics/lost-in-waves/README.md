# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)
Challenge Name: Lost in Waves  
Platform: ehaxCTF 2026  
Category: Forensics (Misc / Signals & Audio)  
Difficulty: Easy  
Time spent: ~40 minutes

## 1) Goal (What was the task?)
The objective was to analyze challenge files related to “covert channels” and recover the hidden flag.  
Success condition was finding a valid flag in the format `EH4X{...}`.

## 2) Key Clues (What mattered?)
- Description hint: “covert channels” suggested hidden communication, not plain file carving.
- Files: `data` (ASCII hex), `data.bin` (RAR archive), folder `0/` with Saleae logic files (`digital-0.bin`, `meta.json`).
- `meta.json` showed Async Serial settings (`115200`, `8N1`, channel 0), which was a strong decoding clue.
- Archive listing required a password, so signal decoding likely provided the key.

## 3) Plan (Your first logical approach)
- Identify file types and relationships (`data` vs `data.bin` vs logic files).
- Decode the logic capture first because it looked like an intentional side-channel.
- Use recovered serial text as archive password.
- Extract final payload (`.wav` files) and decode the modulation inside audio to get the flag.

## 4) Steps (Clean execution)
1. **Action:** Ran `file`, `xxd`, and directory inspection.  
   **Result:** `data.bin` was RAR5 (encrypted). `data` was hex-encoded bytes of the same archive.  
   **Decision:** Password had to be recovered from `0/` capture files.

2. **Action:** Inspected `0/meta.json`.  
   **Result:** Found Async Serial analyzer settings (115200 baud, 8 data bits, no parity, 1 stop bit, channel 0).  
   **Decision:** Decode `digital-0.bin` as UART timing/bitstream.

3. **Action:** Parsed transition deltas from `digital-0.bin` and quantized to UART bit periods.  
   **Result:** Clean decoded text: `ohblimey**ehax` (trailing `\r`).  
   **Decision:** Use it as RAR password.

4. **Action:** Listed/extracted archive with `unrar-nonfree` using password.  
   **Result:** Extracted `1.wav`, `2.wav`, `3.wav`, `4.wav`.  
   **Decision:** Analyze audio for encoded pager/modem text.

5. **Action:** Decoded WAV files with `multimon-ng` (`POCSAG1200`).  
   **Result:** `4.wav` contained message: `Passwordz EH4X{P4g3d_lik3_a_b00k}. Keep it hush, yeah?`  
   **Decision:** Extract flag from message.

## 5) Solution Summary (What worked and why?)
This challenge chained two covert channels: digital logic capture and pager-modulated audio.  
The key pattern was to trust metadata: Saleae session settings revealed UART parameters, which gave the RAR password. After extraction, pager decoding (POCSAG1200) exposed the final plaintext message containing the flag.

## 6) Flag
`EH4X{P4g3d_lik3_a_b00k}`

## 7) Lessons Learned (make it reusable)
- Always inspect analysis/session metadata files (`meta.json`) before brute force.
- In mixed-media forensics, expect staged layers (logic capture -> archive -> audio modulation).
- When archive tools fail, try alternate extractors (`unrar` vs `7z`) and keep moving.
- For suspicious radio-like audio, quickly test `multimon-ng` demodulators.

## 8) Personal Cheat Sheet (optional, but very useful)
- `file <target>` -> quick type fingerprinting.
- `xxd <file>` -> verify headers/structure manually.
- Saleae `meta.json` -> often contains exact decoder settings (baud, parity, channel).
- `7z l -p'<pass>' archive.rar` -> test password quickly.
- `unrar x -p'<pass>' archive.rar out/` -> reliable RAR5 extraction.
- `multimon-ng -t wav -a POCSAG1200 <file.wav>` -> decode pager text from WAV.
