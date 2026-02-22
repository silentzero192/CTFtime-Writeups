# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

Challenge Name: Ghost Ship  
Platform: Bearcat CTF 2026 (BCCTF)  
Category: Misc / Reversing  
Difficulty: Easy  
Time spent: ~40 minutes

## 1) Goal (What was the task?)
The challenge gave one file named `ghost_ship` and a story about symbols on parchment.  
Success was to recover the correct flag in format `BCCTF{...}` that passes the program's check.

## 2) Key Clues (What mattered?)
- File name: `ghost_ship`
- `file ghost_ship` showed it was ASCII text with a very long line (not a native binary)
- The content was made of `><+-.,[]`, which is Brainfuck syntax
- The program prints a prompt asking for a flag, then prints fail/success text
- There are exactly 40 input reads (`,` commands), so expected input length is 40 bytes

## 3) Plan (Your first logical approach)
- Identify file type first to avoid wasting time with wrong tooling.
- Execute/interpret the Brainfuck code to see runtime behavior and prompts.
- Find where success/failure is decided, then extract what the checker compares.
- Use that check as an oracle to recover the flag one character at a time.

## 4) Steps (Clean execution)
1. Action: Ran `file ghost_ship` and `strings ghost_ship`.  
   Result: It is Brainfuck code, not an ELF/PE binary.  
   Decision: Use a Brainfuck interpreter approach.

2. Action: Ran the program through a small local interpreter.  
   Result: It printed ghost-themed text and asked for the flag, then failed.  
   Decision: Reverse the checker logic instead of random brute force.

3. Action: Counted input operations (`,`).  
   Result: Found 40 reads, so the checker expects 40 characters.  
   Decision: Constrain candidate length to 40.

4. Action: Instrumented execution and found the key branch point where a mismatch counter is checked (`ip=9098`).  
   Result: Cell value at that point equals number of wrong positions.  
   Decision: Turn this into a scoring oracle (`lower score = closer to correct flag`).

5. Action: Fixed known format (`BCCTF{` and final `}`), then brute-forced each unknown position over printable ASCII and kept the character with the best score.  
   Result: Score dropped by exactly 1 per correct character until 0.  
   Decision: Reconstructed full flag and validated with full run.

6. Action: Automated the process in `solve.py`.  
   Result: Script compiles a tiny C probe, queries mismatch score, and recovers flag end-to-end.  
   Decision: Use script for reproducible solve.

## 5) Solution Summary (What worked and why?)
The core pattern was a per-character equality check that accumulated mismatches into one counter. By observing that counter before the success/fail branch, I got an oracle: each correct guessed character reduced the counter by 1. This made the challenge solvable deterministically, one position at a time, instead of blind brute force over the full flag space.

## 6) Flag
`BCCTF{N0_moR3_H4un71n6!_N0_M0rE_Gh0575!}`

## 7) Lessons Learned (make it reusable)
- If a file is symbol-heavy ASCII, check esoteric languages (like Brainfuck) early.
- In reversing, always look for decision points (success/fail branch) and inspect nearby state.
- A single numeric side-channel (mismatch count, timing, branch depth) can fully break a checker.
- Constrain search with known flag format and expected input length before brute forcing.

## 8) Personal Cheat Sheet (optional, but very useful)
- `file <target>` -> quick file fingerprinting
- `strings -n 6 <target>` -> extract readable prompts/hints
- Count `,` in Brainfuck -> expected input length
- Watch branch-state cell -> convert checker into oracle
- `python3 solve.py` -> run full automated recovery for this challenge
