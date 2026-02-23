# CTF Writeup

**Challenge Name:** Polly's Key  
**Platform:** Bearcat CTF  
**Category:** Reversing  
**Difficulty:** Medium  
**Time spent:** ~45 minutes

## 1) Goal (What was the task?)
The challenge asked for a valid “key” that both the pirate and parrot would accept.  
Success was printing the final flag in format `BCCTF{...}`.

## 2) Key Clues (What mattered?)
- Single challenge file: `pollys_key`
- `file pollys_key` showed it was a script (not ELF), and it looked intentionally mixed/obfuscated.
- The script ran under both `ruby` and `perl`.
- Story clue said pirate and parrot “spoke at the same time” and “different languages,” hinting both interpreters matter.
- Encrypted output array and MD5-based XOR logic were present in the source.

## 3) Plan (Your first logical approach)
- Inspect file type and strings first to understand what kind of target it is.
- Run the script with both `ruby` and `perl` to confirm the dual-language behavior.
- Extract both validation paths and model each constraint in Python.
- Solve constraints to recover the only valid key, then decrypt the flag.

## 4) Steps (Clean execution)
1. Action: Listed files and checked type (`ls`, `file`).  
   Result: Found one file, `pollys_key`, identified as a Ruby script with polyglot-looking content.  
   Decision: Treat it as an obfuscated script challenge, not binary reversing.

2. Action: Executed with both interpreters (`ruby pollys_key`, `perl pollys_key`).  
   Result: Both executed and performed different checks.  
   Decision: Solve both logic branches, not just one.

3. Action: Recovered effective logic via inspection/deparse/bytecode.  
   Result:  
   - Ruby path enforced: length 50, printable ASCII range, no `^`, uniqueness, ordering rules, and a modular arithmetic primitive-root style constraint.  
   - Perl path enforced: insertion-sort swap profile (`@sArray`) over transformed values and separate ordering checks.  
   Decision: Build a solver that combines both languages’ constraints.

4. Action: Converted constraints to Python and enumerated candidates.  
   Result: Derived valid key candidate and verified it in both interpreters.  
   Decision: Use that key to decrypt the 32-byte encrypted treasure.

5. Action: MD5 nibble XOR decryption against `encTreasure`.  
   Result: Recovered `BCCTF{Th3_P05h_9oLly61Ot_p4rr0t}`.  
   Decision: Finalize solver script for reproducibility.

## 5) Solution Summary (What worked and why?)
The core trick was that `pollys_key` is a Ruby/Perl polyglot, so one input must satisfy two different validator implementations. Ruby constrained the 50-character key to a very specific printable/unique set with modular arithmetic properties, while Perl constrained the transformed ordering through insertion-sort swap counts. Combining both reduced the space to a valid key, and then the script’s MD5-nibble XOR routine directly decrypted the flag.

## 6) Flag
`BCCTF{Th3_P05h_9oLly61Ot_p4rr0t}`

## 7) Lessons Learned (make it reusable)
- When challenge text hints at “two voices/languages,” test multiple runtimes.
- In mixed-language scripts, comments/strings can hide active code paths differently per interpreter.
- Sort-swap count arrays often encode inversion vectors or ranking constraints.
- Reversing gets easier when constraints are translated into a solver instead of manual guessing.

## 8) Personal Cheat Sheet (optional, but very useful)
- `file <target>` → identify artifact type quickly.
- `ruby --dump=insns <script>` → inspect Ruby bytecode path actually executed.
- `perl -MO=Deparse <script>` → view effective Perl code after parsing quirks.
- Pattern: Polyglot challenge → validate behavior in all plausible interpreters early.
- `python3 solve.py` → deterministic recovery of key + flag for this challenge.

## Reproduce
Run:

```bash
python3 solve.py
```

Expected output includes:

```text
[+] flag : BCCTF{Th3_P05h_9oLly61Ot_p4rr0t}
```
