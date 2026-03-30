CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

Challenge Name: Quantum Message  
Platform: ehaxCTF-2026  
Category: Forensics  
Difficulty: Easy  
Time spent: ~35 minutes

## 1) Goal (What was the task?)
The challenge gave a single audio file and a physics-themed hint asking, “who did he call?”.  
Success meant extracting the hidden flag in the required format: `EH4X{...}`.

## 2) Key Clues (What mattered?)
- Prompt keyword: “who did he call?” (strong hint toward phone/telephony tones)
- File provided: `challenge.wav`
- Audio looked normal by metadata, but had repeating structured tones
- Spectrogram showed consistent dual-tone blocks (signal encoding, not random noise)

## 3) Plan (Your first logical approach)
- Check basic file metadata first to confirm type, duration, and any obvious hidden tags.
- Generate a spectrogram to visually detect whether data is encoded in frequency patterns.
- If tone pairs are present, segment by symbol timing and decode as keypad-like values.
- Convert decoded symbols into text/ASCII and validate against `EH4X{...}` format.

## 4) Steps (Clean execution)
1. **Action:** Inspected the file with `file`, `soxi`, and `ffprobe`.  
   **Result:** Found mono float WAV, no useful metadata payloads.  
   **Decision:** Move to signal-domain analysis.

2. **Action:** Generated spectrogram with SoX (`sox challenge.wav -n spectrogram ...`).  
   **Result:** Clear repeating dual-tone pattern appeared across the full audio.  
   **Decision:** Treat it as an encoded tone stream.

3. **Action:** Converted float WAV to PCM16 (`ffmpeg ... challenge_s16.wav`) for easier parsing in Python.  
   **Result:** Same content, easier compatibility for custom decoding scripts.  
   **Decision:** Perform FFT-based per-window frequency extraction.

4. **Action:** Detected dominant low/high tone pairs over short windows, removed 1-frame glitches, and run-length decoded merged repeats.  
   **Result:** Recovered a long digit stream:
   `69725288123113117521101161171099511210412111549995395495395534895539952114121125`  
   **Decision:** Parse as ASCII decimal values.

5. **Action:** Parsed digit stream into ASCII (2–3 digit splits).  
   **Result:** Unique valid plaintext appeared:
   `EH4X{qu4ntum_phys1c5_15_50_5c4ry}`  
   **Decision:** Submit as final flag.

## 5) Solution Summary (What worked and why?)
The core solve was recognizing that the WAV was not meant to be listened to, but interpreted as encoded tone symbols. The spectrogram made this obvious by showing stable, repeated frequency pairs. After segmenting and decoding those tone symbols into numeric output, the stream mapped cleanly to ASCII and produced a valid `EH4X{...}` flag.

## 6) Flag
`EH4X{qu4ntum_phys1c5_15_50_5c4ry}`

## 7) Lessons Learned (make it reusable)
- In forensics audio challenges, always inspect spectrogram early; visuals reveal hidden structure fast.
- “Call”, “dial”, “tone”, or similar wording often hints at telephony-style encoding.
- Run-length cleanup is important when symbols repeat and boundaries blur.
- Converting to a simpler sample format (PCM16) can save time when parser/tool support is limited.

## 8) Personal Cheat Sheet (optional, but very useful)
- `file <audio>` -> Quick type/format check
- `soxi <audio>` / `ffprobe <audio>` -> Detailed audio properties + metadata
- `sox <in.wav> -n spectrogram -o out.png` -> Visual frequency pattern detection
- `ffmpeg -i in.wav -sample_fmt s16 out.wav` -> Compatibility conversion for scripts/tools
- Pattern to remember:  
  Audio Forensics -> metadata -> spectrogram -> detect symbol timing -> decode tones -> parse ASCII/base encodings
