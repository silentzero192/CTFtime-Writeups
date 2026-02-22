# CTF Writeup

**Challenge Name:** Battleship for one  
**Platform:** Bearcat CTF 2026  
**Category:** Misc / Scripting  
**Difficulty:** Medium  
**Time spent:** ~1 hour

## 1) Goal (What was the task?)
The service runs a solo battleship game at `nc chal.bearcatctf.io 45457`.  
Success means clearing the Ultimate Challenge (30 total rounds) and receiving a flag in `BCCTF{...}` format.

## 2) Key Clues (What mattered?)
- `battleship.py` was provided locally.
- Ultimate mode requires: 10 easy + 10 medium + 10 hard wins in a row.
- Each board is built from a fixed `basis` and then shuffled by row/column permutations.
- Guessed cells reveal their real numeric value from the shuffled board.
- The ship is value `0`, and each difficulty has fixed original coordinates of `0` in the basis.

## 3) Plan (Your first logical approach)
- Read source first to avoid blind guessing over netcat.
- Model what shuffle does: row permutation + column permutation only.
- Use revealed cell values to infer which original row/column each current row/column maps to.
- Automate all 30 rounds with a script so timing and parsing stay reliable.

## 4) Steps (Clean execution)
1. Action: Read `battleship.py` and inspect `Board.shuffle`, `guess`, and Ultimate flow.  
   Result: Found deterministic structure (permutations), fixed basis arrays, and strict attempt limits.  
   Decision: Solve by math/reconstruction, not brute force.

2. Action: Build a value-to-original-position map from each basis (`value -> (orig_row, orig_col)`).  
   Result: Any revealed value immediately leaks original row/column identity.  
   Decision: Probe controlled cells and recover where `0` moved.

3. Action: Probe diagonal cells `(k, k)` while parsing the printed board after each guess.  
   Result: From revealed value at `(k, k)`, determine current row `k` maps to some original row and current col `k` maps to some original col.  
   Decision: Stop probing early once both target row and target column for `0` are known.

4. Action: Fire final guess at recovered `(row_target, col_target)` for that round.  
   Result: Round is won with minimal required probes.  
   Decision: Repeat for all 30 rounds.

5. Action: Harden socket reads (buffered parsing + marker-based receive + timeout tolerance).  
   Result: Stable run through hard rounds and final flag extraction.  
   Decision: Keep this in final `solve.py`.

## 5) Solution Summary (What worked and why?)
The shuffle never mixes values arbitrarily; it only permutes rows and columns.  
So each revealed number acts like a coordinate oracle: by looking up that number in the original basis, we learn the original row/column pair that produced the current cell. Repeating this for a few probes identifies where original row/column of `0` moved in the shuffled board. Once both are known, a single final shot hits the ship. Automating this over all 30 rounds yields the flag reliably.

## 6) Flag
`BCCTF{S0r7_0f_L1k3_SuD0ku}`

## 7) Lessons Learned (make it reusable)
- In puzzle/game CTFs, read source before interacting with remote.
- Permutation-based shuffles are often invertible from partial leaks.
- Revealed output values can leak hidden state more than intended.
- Stable socket buffering matters as much as core exploit logic.

## 8) Personal Cheat Sheet (optional, but very useful)
- `python3 solve.py` -> run full automated solver.
- `python3 solve.py chal.bearcatctf.io 45457` -> explicit host/port.
- Pattern: if game state is shuffled but not randomized per-value, map outputs back to original index positions.
- Pattern: parse from the latest board marker (`Attempts left:`) to avoid mixed output chunks.
