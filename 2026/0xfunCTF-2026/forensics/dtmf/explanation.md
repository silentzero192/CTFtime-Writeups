# DTMF (Forensics) — 0xfun CTF 2026

## Challenge Overview

In this challenge, a file named `message.wav` was provided.  
The objective was to analyze the audio file and recover the hidden flag using forensic techniques.

---

## Step 1 — Decode DTMF Audio

Since the challenge title referenced **DTMF (Dual-Tone Multi-Frequency)**, the first step was to decode the tones inside the audio file.

I uploaded `message.wav` to an online DTMF decoder.

The decoded output was a long binary string:

```
010011010100100001001010011101000101101000110010011100000011011101010110010010000101010101111000011000100101010001000110011001100101100101101010010100100110111101011000001100100110110001111010010110010111101001010110011001100110010001101101001101010011000001100011011011100011000000111101
```

---

## Step 2 — Convert Binary to Base64

Using CyberChef:

- Input format: Binary
- Output format: ASCII

The binary converted to:

```
MHJtZ2p7VHUxbTFfYjRoX2lzYzVfdm50cn0=
```

This is clearly a **Base64-encoded string**.

---

## Step 3 — Decode Base64

Again using CyberChef, I decoded the Base64 string:

```
MHJtZ2p7VHUxbTFfYjRoX2lzYzVfdm50cn0=
→ 0rmgj{Tu1m1_b4h_isc5_vntr}
```

This looked like a substituted or encrypted flag.

---

## Step 4 — Metadata Analysis (EXIF Inspection)

Next, I examined the metadata of the audio file using:

```bash
exiftool message.wav
```

The output revealed:

```
Comment : uhmwhatisthis
Software: Lavf60.16.100
Duration: 0:00:50
```

The **Comment field** contained:

```
uhmwhatisthis
```

This strongly suggested it could be used as a decryption key.

---

## Step 5 — Vigenère Cipher Decryption

The decoded text:

```
0rmgj{Tu1m1_b4h_isc5_vntr}
```

appeared to be encrypted using a substitution cipher.

I used a **Vigenère cipher decoder**, with the key:

```
uhmwhatisthis
```

After decryption, the final flag was revealed:

```
0xfun{Mu1t1_t4p_plu5_dtmf}
```

---

## Final Flag

```
0xfun{Mu1t1_t4p_plu5_dtmf}
```

---

## Conclusion

This challenge required:

- DTMF tone decoding
- Binary to ASCII conversion
- Base64 decoding
- Metadata inspection using `exiftool`
- Vigenère cipher decryption

The flag was hidden across multiple layers of encoding and encryption, combining audio signal analysis with classical cryptography and metadata forensics.

