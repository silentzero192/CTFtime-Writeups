# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

**Challenge Name:** The Kamchatka Taps  
**Platform:** upsideCTF 2026  
**Category:** Reversing  
**Difficulty:** Easy  
**Time spent:** ~15 minutes

## 1) Goal (What was the task?)
The challenge gave a single audio file and said the signal sounded like someone rhythmically banging on a heating pipe from a prison in Kamchatka. The objective was to decode that message, identify who was trapped inside, and submit it in the format `CTF{...}`.

## 2) Key Clues (What mattered?)
- The description used the words "faint audio signal" and "rhythmically banging on a heating pipe"
- The only provided file was `kamchatka_taps.wav`
- The challenge explicitly said to "decode the message"
- The audio sounded structured, which suggested an intentional timing-based encoding
- Repeated short and long tap durations pointed toward Morse code timing

## 3) Plan (Your first logical approach)
- Check what files were provided and confirm whether the challenge was only about the audio file
- Inspect the WAV file format and duration to understand what kind of signal it contained
- Measure the timing of the sound bursts to see whether they matched a known encoding system
- Try decoding the pattern as Morse code because the bursts looked like short and long signals with separated gaps

## 4) Steps (Clean execution)
1. **Action:** Listed the challenge files.  
   **Result:** There was only one file: `kamchatka_taps.wav`.  
   **Decision:** Focus the solve entirely on the audio signal.

2. **Action:** Checked the audio properties with tools like `file`, `soxi`, and `ffprobe`.  
   **Result:** The file was a normal mono PCM WAV file, about 20.4 seconds long.  
   **Decision:** Since nothing unusual appeared in the container format, the real data was likely in the audio timing itself.

3. **Action:** Examined the waveform and grouped the signal into tone bursts and silent gaps.  
   **Result:** The audio had very clean timing units:
   - `0.1s` tone
   - `0.3s` tone
   - `0.1s` gap
   - `0.3s` gap
   - `1.0s` gap
   **Decision:** This strongly matched Morse code timing:
   - short tone = dot
   - long tone = dash
   - medium gap = next letter
   - long gap = next word

4. **Action:** Converted the timing pattern into Morse symbols and decoded each group.  
   **Result:** The message decoded to:
   `CTF THE AMERICAN IS ALIVE`
   **Decision:** Since the flag format was `CTF{...}`, convert the decoded phrase into the expected submission format.

5. **Action:** Wrapped the decoded message as a flag.  
   **Result:** Final flag:
   `CTF{THE_AMERICAN_IS_ALIVE}`
   **Decision:** Submit the flag.

## 5) Solution Summary (What worked and why?)
The solve worked because the audio was not random noise or hidden metadata. It was a timing-based signal with very regular short and long bursts, which is a classic sign of Morse code. Once I measured the tone lengths and gap lengths, the structure became obvious: short burst for dot, long burst for dash, medium gap for a new letter, and long gap for a new word. Decoding those groups revealed the sentence, which could then be formatted directly as the flag.

## 6) Flag
`CTF{THE AMERICAN IS ALIVE}`

## 7) Lessons Learned (make it reusable)
- When a challenge gives only an audio file, always check whether the information is in the sound itself, not just the file metadata.
- Repeated short and long timings are a strong hint for Morse code or another timing-based encoding.
- Measuring burst lengths and silence lengths can be more useful than trying to listen manually.
- A clean signal often means the challenge author wants pattern recognition, not heavy audio forensics.

## 8) Personal Cheat Sheet (optional, but very useful)
- `file <name>` -> quick check of file type and encoding
- `soxi <name>` -> simple audio metadata like duration, channels, and sample rate
- `ffprobe <name>` -> detailed media stream information
- Waveform timing analysis -> useful when audio contains pulses, taps, or beeps
- Pattern to check early -> audio with structured short/long sounds often means Morse code
