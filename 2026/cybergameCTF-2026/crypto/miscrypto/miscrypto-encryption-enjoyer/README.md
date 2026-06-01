# Encryption Enjoyer - Writeup

**Challenge Name:** `miscrypto - encryption enjoyer`  
**Platform:** `CyberGame CTF 2026`  
**Category:** `Crypto / Reversing`  

## 1) Goal (What was the task?)
We were given one recovered file named `encrypted` from a compromised server.  
Success condition was to recover the original plaintext flag in format `SK-CERT{...}`.

## 2) Key Clues (What mattered?)
- Only one artifact existed: `encrypted` (no source code, no hint file).
- Byte distribution showed strong repetition, not high-entropy random ciphertext.
- Repeating patterns suggested repeating-key XOR or layered custom obfuscation.
- Flag format was known: `SK-CERT{...}`.

## 3) Plan (Your first logical approach)
- Check file type, size, and byte-level structure to identify if encryption is standard or custom.
- Test for periodicity to detect repeating-key XOR key length.
- Recover and verify stage-1 key by checking if decryption yields a valid known file format.
- Reverse the decrypted file to extract final payload/key and decode the flag.

## 4) Steps (Clean execution)
1. Action: Fingerprint the challenge file.
   - Commands:
   ```bash
   file encrypted
   wc -c encrypted
   xxd -g 1 -l 256 encrypted
   ```
   - Result: `encrypted` was raw data with visible repeating byte patterns.
   - Decision: Investigate repeating-key behavior.

2. Action: Detect key periodicity statistically.
   - Command used (Python one-liner style):
   ```bash
   python - <<'PY'
   b=open('encrypted','rb').read()
   for k in range(1,65):
       eq=sum(1 for i in range(len(b)-k) if b[i]==b[i+k])/(len(b)-k)
       print(k,eq)
   PY
   ```
   - Result: Strong spikes at multiples of `10` (10, 20, 30, ...).
   - Decision: Assume repeating XOR key length is 10.

3. Action: Recover the 10-byte key from dominant bytes per modulo-10 position.
   - Command:
   ```bash
   python - <<'PY'
   from collections import Counter
   b=open('encrypted','rb').read()
   for i in range(10):
       print(i, Counter(b[i::10]).most_common(1))
   PY
   ```
   - Result: Most common bytes by position gave key:
     `ab 31 b3 b2 b1 32 b4 b0 b9 32`
     -> `ab31b3b2b132b4b0b932`.
   - Decision: Decrypt with this key and validate output format.

4. Action: Decrypt stage 1 and verify file type.
   - Commands:
   ```bash
   python - <<'PY'
   b=open('encrypted','rb').read()
   k=bytes.fromhex('ab31b3b2b132b4b0b932')
   d=bytes(c^k[i%10] for i,c in enumerate(b))
   open('dec_xor_k10.bin','wb').write(d)
   PY
   file dec_xor_k10.bin
   ```
   - Result: Output identified as `PE32+ executable`.
   - Decision: Reverse this PE to locate embedded payload and second key.

5. Action: Extract the second XOR key and encrypted payload from PE sections.
   - Commands:
   ```bash
   objdump -s -j .rdata dec_xor_k10.bin | sed -n '1,80p'
   objdump -s -j .data dec_xor_k10.bin | sed -n '1,40p'
   ```
   - Result:
     - 7-byte key found in `.rdata`: `af34f010992001`
     - 0x29-byte encrypted payload found at start of `.data` (RVA `0x3000`)
   - Decision: XOR payload with 7-byte repeating key.

6. Action: Final decode.
   - Command:
   ```bash
   python - <<'PY'
   data=bytes.fromhex('fc7fdd53dc7255d450c353cb59719807b44fac5542cc51c525ff556de34daf47aa6c4df070c05eaa5d')
   key=bytes.fromhex('af34f010992001')
   out=bytes(b ^ key[i%len(key)] for i,b in enumerate(data))
   print(out.decode())
   PY
   ```
   - Result: `SK-CERT{d3CRyp73D_5uCce55fulLy_W3LL_D0N3}`
   - Decision: Flag recovered.

## 5) Solution Summary (What worked and why?)
This challenge used two XOR layers. The outer layer was a repeating 10-byte XOR that turned `encrypted` into a valid PE executable. Inside that PE, a second 7-byte repeating XOR decoded a 41-byte payload into the final flag. The solve worked by first identifying periodicity (key length), then extracting keys from structure/statistics and static PE section data.

## 6) Flag
`SK-CERT{d3CRyp73D_5uCce55fulLy_W3LL_D0N3}`

## 7) Lessons Learned (make it reusable)
- Repeating-key XOR leaks periodicity clearly; autocorrelation-style checks quickly reveal key length.
- `file` + `objdump -s` are often enough for malware-style CTF binaries without full dynamic analysis.
- When decrypted data suddenly matches a known format (PE/ZIP/PNG), treat it as a staged container.
- Avoid brute force first; simple stats and structure checks are faster and more reliable.

## 8) Personal Cheat Sheet (optional, but very useful)
- `xxd -g 1 -l 256 <file>` -> quick byte-pattern preview.
- `python` periodic equality scan -> detect likely repeating-key length.
- `Counter(b[i::k])` -> estimate key bytes per key position.
- `file <decrypted_blob>` -> validate if guessed key is correct.
- `objdump -s -j .rdata/.data <pe>` -> read embedded strings/constants/payload bytes.
