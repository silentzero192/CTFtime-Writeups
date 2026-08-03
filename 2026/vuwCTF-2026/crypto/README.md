# VuwCTF 2026 — Crypto Writeups

Solution scripts and full writeups for the crypto challenges.

## Challenges

| Challenge | Difficulty | Type                        | Flag                                     |
| --------- | ---------- | --------------------------- | ---------------------------------------- |
| [nom-nom](nom-nom/) | Easy | RSA low-exponent (e=3) cube-root attack | `VuwCTF{NomPolynomialNom}` |
| [farming](farming/) | Medium | base-3 encoding → bzip2 stream         | `VuwCTF{unfortunate_moos_experience}` |
| [concord](concord/) | Medium | finite-field key-schedule collapse → 256-key brute force | `VuwCTF{crypto_loves_mathematics}` |

Each folder contains:

- the original challenge files
- a `solve.py` solver (run with `python3 solve.py`)
- a `WRITEUP.md` with the full detailed walkthrough

## Quick summary

- **nom-nom** — `e = 3` and both plaintexts are small enough that
  `plaintext^3 < n`, so the ciphertexts are exact cubes. An integer cube root
  recovers `flag_inner` and the full flag without factoring `n`.

- **farming** — the `field_recording` is a herd of "lame cows": every word is
  `M` + a base-3 number (`O=2`, `0=1`, `o=0`). Decoding all 148 words yields a
  bzip2 archive (`BZh91AY&SY...`) that decompresses into an ASCII-moo banner
  containing the flag.

- **concord** — the key schedule's `op(a,b)=(a+1)(b+1)%257-1` is multiplication
  in `F_257` in disguise, so the inner reduction over all 2^30 bytes collapses
  to a constant and the whole AES key depends only on `P = ∏(b+1) mod 257 ∈
  {1..256}`. Brute-forcing those 256 keys recovers the flag in milliseconds.
