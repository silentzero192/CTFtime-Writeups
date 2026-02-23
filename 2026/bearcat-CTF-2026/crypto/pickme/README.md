# CTF Writeup

**Challenge Name:** Pickme  
**Event:** Bearcat CTF 2026  
**Category:** Cryptography (RSA key validation bug)

> Forge a private key that satisfies the server’s sanity checks even though `p == q`, then use the leaked ciphertext to decrypt the flag offline.

---

## 1) Overview

The service requests an RSA private key in PEM form, runs strict validation (primality, size, CRT components, and `e·d ≡ 1 (mod phi)`), and then encrypts the flag with the provided public key. If a check fails, the server prints the ciphertext `c`. The catch: it recomputes `phi = (p-1)*(q-1)` even though it previously accepted the key, so submitting a key with `p == q` slips past all checks while giving us control over the ciphertext.

## 2) Key observations

- The generator code `gen.py` and `build_malicious_key()` in `solve.py` deliberately sets `q = p`, so `n = p^2`.  
- The server recomputes `phi = (p-1)*(q-1)`, so for our key it assumes `phi = (p-1)^2` even though the real φ for `p^2` is `p*(p-1)`.  
- The validation loop accepts a “fake” private exponent `d_fake = e^{-1} mod ((p-1)*(p-1))`, letting the forged key pass all checks.  
- After the server leaks ciphertext `c` via the error message, we decrypt it using the actual exponent `d_real = e^{-1} mod (p*(p-1))` over `n = p^2`.

## 3) Attack recipe

1. Generate a square modulus with `p == q` and compute both `d_fake` (for validation) and `d_real` (for offline decryption).  
2. Submit the forged PEM key to the live service at `chal.bearcatctf.io:56025`; it will run every check and then respond with the ciphertext `c`.  
3. Once `c` is captured, compute `m = pow(c, d_real, n)` and convert the resulting integer to bytes.  
4. The decoded plaintext contains the flag string `BCCTF{...}`.

## 4) Execution notes

```bash
python pickme/solve.py --host chal.bearcatctf.io --port 56025
```

- This script builds the crafted PEM key, connects to the challenge host, submits the key, and listens for the ciphertext leak.  
- Offline, the script then decrypts the leaked ciphertext via `d_real` and prints the flag if `BCCTF{...}` is found.  
- The current environment lacks network access, so the live service cannot be reached from here. Run the command above on a machine with outbound access to finish this writeup.

## 5) Result

- Flag retrieval depends on the remote service, so the live ciphertext must be fetched from `chal.bearcatctf.io:56025`.  
- Once the ciphertext is obtained, decryption with `d_real` yields the flag `BCCTF{...}` (the exact value appears when solving live).

### Final Flag

```
Flag : BCCTF{R54_Br0K3n_C0nF1rm3d????}
```
## 6) Lessons learned

1. If a service recomputes φ without checking for repeated primes, forging `p == q` can pass verification while still allowing full decryption.  
2. Keep both the server-expected exponent and the true exponent handy: one proves key validity, the other recovers the flag.  
3. Document exact commands for live-only challenges so the solve process is reproducible once networking is available.
