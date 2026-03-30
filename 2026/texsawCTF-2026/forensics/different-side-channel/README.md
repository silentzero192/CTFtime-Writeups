# different side channel

Challenge Name: different side channel  
Platform: TexSAW CTF 2026  
Category: Forensics  
Difficulty: Medium  
Time spent: About 20 minutes

## 1) Goal (What was the task?)
We were given 500 power traces from a hardware AES encryption device, along with the 16-byte plaintext used for each trace and an encrypted flag file.  
The goal was to recover the unknown AES key from the side-channel leakage, decrypt the flag, and output it in the format `texsaw{...}`.

## 2) Key Clues (What mattered?)
- The description explicitly mentioned power traces, AES, known plaintexts, and an unknown secret key.
- The files were `plaintexts.npy`, `traces.npy`, and `encrypted_flag.bin`.
- `plaintexts.npy` had shape `(500, 16)`, which strongly suggested AES block inputs.
- `traces.npy` had shape `(500, 100)`, which meant each encryption produced a short captured power trace.
- Side-channel AES challenges with known plaintexts usually point to a first-round Correlation Power Analysis (CPA) attack.
- The flag file was 64 bytes long, which suggested AES block encryption and a possible IV-prepended CBC layout.

## 3) Plan (Your first logical approach)
- Inspect the NumPy files first to confirm the trace format, number of samples, and plaintext size.
- Assume the device leaks information during the first AES round and test a Hamming-weight leakage model on `SBox(plaintext_byte XOR key_byte)`.
- Recover the AES key one byte at a time by finding the key guess with the highest correlation to the traces.
- Use the recovered key to try common AES decryption layouts for the flag file, especially CBC with a prefixed IV.

## 4) Steps (Clean execution)
1. I listed the files and confirmed the challenge only contained `plaintexts.npy`, `traces.npy`, and `encrypted_flag.bin`.  
   Result: This looked like a clean offline side-channel challenge with no extra noise.  
   Decision: Load the NumPy arrays and inspect their shapes.

2. I loaded the arrays with Python and checked their structure.  
   Result: `plaintexts.npy` was `(500, 16)` and `traces.npy` was `(500, 100)`. That matched 500 AES encryptions with 16-byte inputs and 100 power samples per trace.  
   Decision: Try CPA on the first AES round.

3. I used the standard AES S-box and built a Hamming-weight leakage model for each key-byte guess from `0x00` to `0xff`.  
   Result: For each byte position, one candidate had a much stronger correlation peak than the others.  
   Decision: Assemble those 16 best guesses into the full AES-128 key.

4. The recovered key was `66dce15fb33deacb5c0362f30e95f52e`.  
   Result: The key looked stable and believable because every byte had a clear winning correlation score.  
   Decision: Decrypt `encrypted_flag.bin` with AES and test likely modes.

5. I first tried ECB, which did not produce readable output. Then I tried CBC.  
   Result: Using the first 16 bytes of the file as the IV and decrypting the remaining bytes produced a padded plaintext containing the flag.  
   Decision: Remove the PKCS#7 padding and verify the flag format.

6. The final plaintext was `texsaw{d1ffer3nti&!_p0w3r_@n4!y51s}`.  
   Result: It matched the required format exactly.  
   Decision: Save the recovery process in `solve.py` so the solve is reproducible.

## 5) Solution Summary (What worked and why?)
The core idea was that the AES device leaked data-dependent power consumption during encryption. Because the plaintexts were known, I could guess each key byte, compute the first-round intermediate value `SBox(plaintext_byte XOR key_byte)`, convert that to a Hamming-weight prediction, and compare that prediction against the real traces using correlation. The correct key guess aligned with the device's leakage much better than the wrong guesses, which revealed the AES key. Once the key was known, the encrypted flag was straightforward to decrypt using AES-CBC with the first block used as the IV.

## 6) Flag
`texsaw{d1ffer3nti&!_p0w3r_@n4!y51s}`

## 7) Lessons Learned (make it reusable)
- If a challenge gives known plaintexts and power traces for AES, first-round CPA should be one of the first things to try.
- A simple Hamming-weight leakage model is often enough for beginner and intermediate side-channel challenges.
- When decrypted data looks almost correct but has junk at the start, check whether the ciphertext includes an IV prefix.
- Clean data inspection early on saves time because shapes and file lengths often reveal the intended attack path.

## 8) Personal Cheat Sheet (optional, but very useful)
- `np.load("file.npy")` -> load NumPy trace or plaintext data quickly.
- `python solve.py` -> rerun the full CPA attack and flag decryption.
- `xxd -g 1 encrypted_flag.bin` -> inspect ciphertext size and block layout.
- Pattern: AES + known plaintexts + power traces -> test CPA with `HW(SBox(pt ^ key_guess))`.
- Pattern: AES ciphertext file with block-aligned length -> check ECB, CBC with zero IV, and CBC with the first block as IV.
