Challenge Name: transformers
Platform: UpsideCTF 2026
Category: Forensics
Difficulty: Medium
Time spent: ~1 hour 20 minutes

## 1) Goal (What was the task?)
The challenge gave a single artifact named `file` and asked for the flag in the format `CTF{...}`.

Success meant figuring out what the file really was, analyzing it properly, and recovering the hidden flag.

## 2) Key Clues (What mattered?)
- The artifact had no extension, so identifying the real file type was important.
- `file file` showed it was an MP3 audio file.
- Basic checks like `strings`, `binwalk`, and metadata review did not reveal the flag directly.
- The audio behaved strangely in stereo analysis, especially in the left-right difference channel.
- The side channel showed highly structured short and long pulses instead of normal music.

## 3) Plan (Your first logical approach)
- First, identify the unknown file type and check for obvious metadata or embedded data.
- Next, test common forensics paths: strings, metadata, appended payloads, and spectrogram inspection.
- When those did not work, move into audio-specific analysis.
- Compare channels and inspect the stereo difference signal for hidden timing-based data.

## 4) Steps (Clean execution)
1. I identified the file type.
   Result: `file file` reported an MP3 audio file.
   Decision: Treat the artifact as audio instead of a generic binary blob.

2. I checked easy wins first.
   Action: Used `strings`, `exiftool`, `ffprobe`, and `binwalk`.
   Result: No obvious flag, no useful embedded archive, and only normal MP3 metadata.
   Decision: Move to audio steganography techniques.

3. I generated spectrograms and separated channels.
   Action: Exported `left.wav`, `right.wav`, `mid.wav`, and `side.wav`.
   Result: The stereo difference (`side.wav`) looked much more structured than the normal audio.
   Decision: Focus on `side.wav`.

4. I measured silence and burst timing in `side.wav`.
   Action: Used `ffmpeg` with `silencedetect` to extract timing patterns.
   Result: The bursts were repeating in short and long lengths, roughly like Morse timing.
   Decision: Try decoding the timing as a dot/dash style signal.

5. I tested different interpretations of the pulse stream.
   Action: Tried several mappings for tone/gap ownership, short vs long, and letter separators.
   Result: One specific mapping produced readable text:
   `CTF,TH3.FL4Y3D.9UB6M,`
   Decision: Interpret the surrounding commas as stand-ins for `{` and `}`.

6. I reconstructed the final flag.
   Result: `CTF{TH3.FL4Y3D.9UB6M}`

Important commands/tools used:

```bash
file file
exiftool file
ffprobe -hide_banner file
binwalk file
ffmpeg -y -i file -filter_complex "[0:a]pan=mono|c0=c0-c1" side.wav
ffmpeg -hide_banner -i side.wav -af silencedetect=noise=-30dB:d=0.1 -f null -
```

## 5) Solution Summary (What worked and why?)
The important idea was that the flag was not stored as plain metadata or as an appended file. The real signal was hidden in the stereo difference channel of the MP3. Once I isolated that side channel, the audio was no longer “music-like” and instead became a timing pattern with short and long bursts. Decoding that timing as a Morse-like sequence revealed the hidden text, and the punctuation was then converted into the expected flag braces.

## 6) Flag
`CTF{TH3.FL4Y3D.9UB6M}`

## 7) Lessons Learned (make it reusable)
- When an audio file looks normal at first, always compare left, right, mid, and side channels.
- If strings/binwalk/metadata fail, shift to format-specific analysis instead of repeating generic checks.
- `silencedetect` is very useful when a hidden signal is based on timing or pulses.
- In audio stego challenges, the final hidden text may be close to readable but still require a small formatting interpretation.

## 8) Personal Cheat Sheet (optional, but very useful)
- `file <artifact>` -> Identify unknown file types quickly.
- `exiftool <file>` -> Check metadata for easy clues.
- `binwalk <file>` -> Look for embedded payloads or appended data.
- `ffmpeg ... pan=mono|c0=c0-c1` -> Extract stereo difference channel.
- `ffmpeg ... silencedetect=...` -> Measure burst/silence timing in audio.
- Pattern to remember: Audio forensics often hides data in spectrograms, channel differences, reversal, or timing-based pulse streams.
