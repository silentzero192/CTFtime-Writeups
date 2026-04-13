# Sloppy Sauce - Writeup
**Challenge Name**: `Sloppy Sauce`
**Platform**: `CodeVinci CTF`
**Category**: `Crypto`

## Goal (What was the task?)
The lab asked me to interact with a remote elliptic-curve service, collect calibration data for different custom curves, and ultimately recover a single 64-bit master scalar that unlocks the flag. Success meant submitting the correct scalar value that the service accepts.

## Key Clues (What mattered?)

- Prompt text “custom curve calibration oracle” and “Orbit preview (debug utility)” hinted that the challenge was about elliptic-curve arithmetic.
- Legacy canary (325) was required for every curve calibration request and never changed during the session, so it became a constant overhead.
- Each calibration response reported Q = d·G on a curve with a small, known-order subgroup (orders remained under ~10k), which meant I could recover d modulo each subgroup order.
- The session fingerprint, budget, and instructions about selecting option [3] repeatedly confirmed the workflow.

## Plan (Your first logical approach)

- Connect via `nc sloppysauce.codevinci.it 9976` and enumerate the menu to understand what data each option returns.
- Use option [2] repeatedly with different custom curves to gather Q_debug/Q and note the curve parameters and subgroup orders.
- For each curve, compute discrete logarithms in Python (since orders were small) to get congruences for d, then combine them via CRT to get the unique 64-bit scalar.

## Steps (Clean execution)

1. Connected to the service, selected option [2] repeatedly with various valid curves (after supplying `legacy_canary = 325`) and recorded each curve’s order plus the Q point returned for `Q = d·G`.
2. For every recorded curve, translated the curve parameters into Python code to brute-force `d mod order` by iteratively adding G until reaching Q—orders were small enough (~3k–10k) for this.
3. Applied the incremental CRT merge of all congruences to obtain a single large modulus congruence and reduced it to the 64-bit range the service expected.
4. Returned to the service, selected option [4], provided the computed scalar `10011339086741369087`, and received `ACCESS GRANTED` plus the flag.

## Solution Summary (What worked and why?)
Each calibration curve effectively gave me a modular equation for the unknown master scalar because Q = d·G lay in a known small-order subgroup. Brute-forcing the discrete log for those small orders yielded congruences `d ≡ ki mod ni`, and combining them via CRT produced the unique scalar the server was expecting. Submitting that scalar unlocked the flag.

## Flag
`CodeVinci{cust0m_curv3s_4r3nt_4_sl0pp3rs}`

## Lessons Learned (make it reusable)

- Small-order curve calibrations let you recover scalar bits piecewise and stitch them together via CRT.
- Always harvest enough independent congruences so the combined modulus exceeds the target scalar size before reducing back to the required bit-length.
- Remember to track static overheads like the legacy canary—forgetting it will abort the oracle calls.
- When remote sessions timeout, reconnect quickly and reuse the deterministic fingerprint/key state.

## Personal Cheat Sheet

- `nc sloppysauce.codevinci.it 9976` → interact with the challenge menu.
- Option [2] plus `legacy_canary` → calibrates a custom curve and returns Q = d·G.
- Python brute-force discrete log → find `d mod order` for small subgroups.
- CRT merging → combine congruences until overall modulus > 2^64, then reduce to 64 bits.
