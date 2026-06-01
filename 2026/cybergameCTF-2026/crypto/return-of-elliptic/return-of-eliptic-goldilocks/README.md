# Return of Eliptic - Goldilocks

**Challenge Name:** `Return of Eliptic - Goldilocks`  

**Platform:** `CybergameCTF 2026`  

**Category:** `Crypto`

1) **Goal (What was the task?)**
- Recover a valid signature over the provided Ed448-like setup and use it to decrypt `flag.enc` via `decrypt_with_signature`, yielding the SK-CERT flag.

2) **Key Clues (What mattered?)**
- `handout.py` implementing Ed448-style verification but summing two public points (`PUB_LEFT` + `PUB_RIGHT`).
- `PUB_LEFT` and `PUB_RIGHT` encode points that individually have large order, but `effective_pub()` has order 4 after addition.
- The decryption routine simply XORs `flag.enc` with a SHAKE-256 stream keyed by the recovered signature, so any valid signature unlocks the ciphertext.
- Known flag format `SK-CERT{...}`.

3) **Plan (Your first logical approach)**
- Inspect `handout.py` to understand the curve implementation, signature format, and how decryption checks a signature before deriving the keystream.
- Compute the order of the effective public key returned by `effective_pub()` to check for weaknesses.
- Forge a signature by exploiting the small order (4) of `A = effective_pub()` and satisfy the verification equation with a small search.

4) **Steps (Clean execution)**
1. Run a quick Python snippet to decode `PUB_LEFT`/`PUB_RIGHT`, confirm the curve operations, and observe that `point_add(left, right)` yields a point of order 4 while the individual points contribute to the script’s “one curve too big, one too small” hint.
2. Build `solve.py` that iterates small `S` values, computes `R = S*BASE - c*A` for `c` in `0..3`, and checks if the SHAKE-derived `k` satisfies `k % 4 == c`, ensuring verification succeeds.
3. Use the forged signature from `solve.py` with `decrypt_with_signature` to XOR `flag.enc` and reveal the flag.

5) **Solution Summary (What worked and why?)**
- The challenge’s hint and code revealed that the “effective” public key had order 4, turning what should be a full Ed448 solve into a brute-force over just four group elements. By expressing `R` as `S*BASE - c*A` and checking whether the derived scalar `k` matched `c mod 4`, I produced a valid signature that passes `verify()` and feeds the decryption routine.

6) **Flag**
 `SK-CERT{1_d0n7_kn0w_why_7h3y_d0n7_us3_7h15_curv3_t00_much}`

7) **Lessons Learned (make it reusable)**
- Small-order public keys drastically weaken signature schemes; always check the group order when people combine points.
- When a verification routine uses SHAKE directly with known inputs, it is practical to search small scalar spaces to satisfy congruence relations.
- Next time, start by confirming point orders before assuming the hardness of the discrete log on the curve.
- Avoid trusting that the “effective” public key automatically inherits the full base order—summations can shrink the subgroup.

8) **Personal Cheat Sheet (optional, but very useful)**
- `python3 handout.py`: inspect constants, curve parameters, and `effective_pub()` logic.
- `scalar_mul(BASE, S)` + `point_add`/`point_neg`: brute-force signatures when `A` has very small order.
- `decrypt_with_signature(sig)`: once a signature verifies, the flag is just `SHAKE(sig | stuff) XOR flag.enc`.
