# CTF Writeup

**Challenge Name:** stratogreet  
**Platform:** Blitz CTF 2025
**Category:** Misc  
**Difficulty:** Easy  
**Time Spent:** ~25 minutes  

---

## 1) Goal (What was the task?)

We were given a single audio file:

```
stratogreet.wav
```

The challenge description mentioned:

> A strange signal was intercepted during a satellite pass. Hidden within it lies a clue to a historic space mission. Recover the information and submit the exact launch date of the mission in the format:  
> `Blitz{yyyy_mm_dd}`

The goal was to extract hidden information from the audio file and determine the exact launch date of the referenced historic space mission.

---

## 2) Key Clues (What mattered?)

- File type:
  ```bash
  file stratogreet.wav
  ```
  Output:
  ```
  RIFF WAVE audio, IEEE Float, mono 44100 Hz
  ```
- Description mentioned:
  - “satellite pass”
  - “intercepted signal”
- Audio signal sounded like digital tones, not speech
- Strong hint toward **SSTV (Slow Scan Television)**

---

## 3) Plan (Your first logical approach)

- Listen to the audio file to understand its nature.
- If it sounds like encoded tones (similar to ISS transmissions), consider SSTV.
- Use an SSTV decoding tool to extract the transmitted image.
- Analyze the decoded image to identify the mission.
- Search for the mission’s launch date.

---

## 4) Steps (Clean execution)

### Step 1: Inspect the Audio File

```bash
file stratogreet.wav
```

Confirmed it is a WAV audio file.

Listening to it revealed structured digital tones — typical of **SSTV transmissions** used in amateur radio and by the ISS.

---

### Step 2: Identify as SSTV

Given:
- Satellite reference
- Radio-like tones
- Space-related hint

This strongly suggested **Slow Scan Television (SSTV)**.

SSTV is used to transmit images over radio signals, commonly by amateur radio operators and occasionally by the ISS.

---

### Step 3: Decode Using QSSTV (Linux)

Installed and launched QSSTV:

```bash
sudo apt install qsstv
qsstv
```

- Played `stratogreet.wav` into QSSTV.
- The software automatically detected and decoded the SSTV signal.

This produced an image (`qsstv.png`).

---

### Step 4: Analyze the Decoded Image

The decoded image clearly referenced:

```
Apollo–Soyuz Mission
```

This is the **Apollo–Soyuz Test Project (ASTP)** — a historic joint US–Soviet space mission.

---

### Step 5: Find Launch Date

A simple search for:

```
Apollo Soyuz launch date
```

Result:

- Launch Date: **July 15, 1975**

Formatted as required:

```
1975_07_15
```

---

## 5) Solution Summary (What worked and why?)

The challenge required recognizing the audio as an **SSTV signal**.

Key idea:
- Satellite + strange signal → SSTV
- Decode SSTV → reveals image
- Image references historic mission
- Search mission launch date
- Format correctly as flag

The challenge tested signal recognition rather than cryptography.

---

## 6) Flag

```
Blitz{1975_07_15}
```

---

## 7) Lessons Learned

- Strange radio-like audio often indicates SSTV.
- Always listen to provided audio files in Misc challenges.
- Satellite + signal hints strongly point to amateur radio protocols.
- Recognizing patterns (SSTV tones) saves time.
- Image decoding tools like QSSTV are very useful in CTFs.

---

## 8) Personal Cheat Sheet

- `file audio.wav` → Identify audio format  
- If it sounds like modem tones → Consider SSTV  
- Linux tool: `qsstv` → Decode SSTV  
- Space-related hint → Check ISS / historic missions  
- Always format dates exactly as required in the challenge  
