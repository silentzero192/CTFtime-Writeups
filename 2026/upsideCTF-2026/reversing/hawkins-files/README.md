# Hawkins File Writeup

Challenge Name: Hawkins File  
Platform: UpSide CTF 2026  
Category: Reversing  
Difficulty: Easy  
Time spent: ~20 minutes

## 1) Goal (What was the task?)
The task was to analyze a provided Android APK, ignore the fake leads, figure out how the application builds its decryption key from the Hawkins lab clues, and decrypt the intercepted signal. Success meant recovering the flag in the `CTF{...}` format.

## 2) Key Clues (What mattered?)
- The challenge provided a single APK file: `hawkinsmon.apk`
- The description explicitly mentioned `APK`, `red herrings`, `how the encryption key is assembled from the lab's vitals`, and `decrypt the raw signal`
- The package name inside the app was `com.hawkins.monitor`
- The asset log mentioned `Subject 011 unresponsive` and `Encrypted signal channel open`
- The app included a base64 string that decoded to `the gate is not here, look deeper`, which strongly suggested a decoy rather than the real flag

## 3) Plan (Your first logical approach)
- Start by unpacking and decompiling the APK because the challenge description clearly points to Android reversing.
- Identify the app-specific package and ignore Android framework/library noise.
- Look for code handling authentication, key building, or decryption.
- Recover the encryption key, extract the encrypted blob, and decrypt it directly.

## 4) Steps (Clean execution)
1. I listed the files in the challenge directory and confirmed the only real artifact was `hawkinsmon.apk`.
   Result: The APK was the full challenge surface.
   Decision: Decompile the APK instead of relying on raw `strings` output.

2. I used `apktool` and `jadx` to inspect both resources and source-like Java output.
   Result: The app-specific code was under `com.hawkins.monitor`.
   Decision: Focus only on the Hawkins classes and skip Android support libraries.

3. I checked the app entry point in `MainActivity`.
   Result: There was a base64 string, `dGhlIGdhdGUgaXMgbm90IGhlcmUsIGxvb2sgZGVlcGVy`.
   Decision: Decode it and verify whether it was useful or just misdirection.

4. I decoded that base64 string.
   Result: It became `the gate is not here, look deeper`.
   Decision: Treat it as a red herring and continue tracing the actual validation logic.

5. I followed the button click handler into `GateMonitor.validateCode()`.
   Result: The app read `res/raw/encrypted_signal.bin`, built a key, and XOR-decrypted the file contents before comparing the result against user input.
   Decision: Recover the key parts instead of trying random auth codes.

6. I traced the two methods used to build the key.
   Result: `LabConfig.getKeyPartA()` returned `MIRKWOOD`, and `VitalSignsHelper.getKeyPartB()` reversed `11NEVELE` into `ELEVEN11`.
   Decision: Combine them into the full key: `MIRKWOODELEVEN11`.

7. I extracted the encrypted raw file and reproduced the XOR decryption locally.
   Result: Decrypting `encrypted_signal.bin` with the repeating key `MIRKWOODELEVEN11` produced the plaintext flag.
   Decision: Verify the output matched the expected `CTF{...}` format.

## 5) Solution Summary (What worked and why?)
The core idea was that the app did not store the flag in plain text, but it did contain everything needed to reconstruct the decryption key. One class returned the first half of the key, another reversed a string tied to Subject 011 to produce the second half, and `GateMonitor` used that combined value as a repeating XOR key over the encrypted raw resource. Once I ignored the fake hint in `MainActivity` and followed the actual validation path, the flag decrypted immediately.

## 6) Flag
`CTF{th3_g4t3_1s_0p3n_d0_y0u_c0py}`

## 7) Lessons Learned (make it reusable)
- In APK reversing, always isolate the app package first so you do not waste time in library code.
- A suspicious base64 string in the main activity is not always the answer; it can be a deliberate hint to keep digging.
- When a challenge mentions logs, vitals, or subject numbers, those values often feed directly into key generation.
- For mobile reversing, following the actual button handler and validation method is usually faster than guessing inputs.

## 8) Personal Cheat Sheet (optional, but very useful)
- `unzip -l file.apk` -> quickly inspect APK contents
- `aapt dump badging file.apk` -> identify package name and launch activity
- `apktool d file.apk -o out` -> decode resources and smali
- `jadx -d out file.apk` -> get readable Java-like code
- `rg -n "key|decrypt|encrypt|auth|flag|Cipher"` -> fast way to locate useful code paths
- Pattern: if an APK contains a `raw` resource and a validation function, check whether the app decrypts that resource at runtime
