# ragebait Writeup

Challenge Name: `ragebait`  
Platform: `Texsaw CTF 2026`  
Category: `Reversing`  
Difficulty: `Medium`  
Time spent: `About 10 minutes`

## 1) Goal (What was the task?)
The goal was to reverse a stripped ELF binary and recover the real flag in the format `texsaw{...}`.

Success meant finding an input that the binary actually accepts, not just a fake flag hidden in strings or printed by a decoy path.

## 2) Key Clues (What mattered?)
- The challenge file was a single stripped 64-bit ELF named `ragebait`
- `strings` immediately showed several suspicious `texsaw{...}` values
- The binary only accepted an argument of length `32`
- `main` hashed the first `9` bytes and used the result to jump through a table of `1009` handlers
- Many handlers were obvious decoys: fake success messages, troll errors, or `/bin/sh` execution
- One handler used the whole input and compared computed values against fixed constants

## 3) Plan (Your first logical approach)
- Check the binary type, imports, strings, and runtime behavior to see whether this was a normal ELF or some packed trick.
- Disassemble `main` first, because that usually reveals how input is validated.
- Treat all embedded flags as suspicious until I found the real validation path.
- Once the real checker was found, turn its math into a direct recovery problem instead of brute forcing.

## 4) Steps (Clean execution)
1. Action: Ran basic triage with `file`, `readelf`, and `strings`.
   Result: The file was a stripped 64-bit ELF with very few imports and several embedded fake-looking flags.
   Decision: Ignore the obvious strings and find the real control flow.

2. Action: Disassembled `main`.
   Result: The program required exactly one argument of length `32`. It hashed the first `9` bytes with FNV-1a and reduced the result modulo `1009`, then used that value as an index into a function-pointer table.
   Decision: The binary was routing input into one of many handlers, so the fake flags were likely spread across those handlers.

3. Action: Mapped the handler table and sampled several handlers with `objdump` and emulation.
   Result: Most handlers were decoys. Some printed fake success flags, some printed troll messages, and some tried to call `/bin/sh`.
   Decision: Keep looking for a handler that actually uses the full input in a meaningful way.

4. Action: Classified handlers and searched for one that read the full candidate string instead of only the prefix.
   Result: Handler bucket `714` was the real one. It processed all `32` bytes into four separate 64-bit accumulators and compared them against four hardcoded constants.
   Decision: Reverse the math directly instead of symbolic execution or brute force.

5. Action: Recovered the recurrence used by the real checker.
   Result: For each of the four groups of characters, the update rule was:

   ```text
   acc = byte + 131 * acc
   ```

   Characters were split by index modulo `4`, so positions `0,4,8,...` fed one accumulator, positions `1,5,9,...` fed the next, and so on.
   Decision: Reverse each accumulator from its final constant using repeated modulo/division by `131`.

6. Action: Solved each accumulator independently.
   Result: The recovered character groups were:

   - Group 0: `taV_4m06`
   - Group 1: `ewhUkE_r`
   - Group 2: `x{Y_3_4y`
   - Group 3: `sVdM_sn}`

   Interleaving those groups by position reconstructed the full flag candidate.
   Decision: Verify it in the binary.

7. Action: Ran the binary with the reconstructed 32-byte string.
   Result: The binary printed the real success message and echoed the flag back.
   Decision: Flag confirmed.

## 5) Solution Summary (What worked and why?)
The key pattern was misdirection. The binary was designed to waste time with fake flags, fake success handlers, troll messages, and even shell execution paths. The real solve came from ignoring the bait, reversing `main`, and identifying the one handler that actually validated the whole input. That handler reduced the problem to four independent polynomial-style recurrences, and because the base was `131`, each group could be reversed cleanly with repeated modulo and division. Once those groups were interleaved, the correct flag dropped out immediately.

## 6) Flag
`texsaw{VVhYd_U_M4k3_mE_s0_4n6ry}`

## 7) Lessons Learned (make it reusable)
- Never trust flags from `strings` in a reversing challenge, especially when the challenge name suggests bait or trolling.
- Always disassemble `main` early; it often reveals input length checks, dispatch logic, and the real validation shape.
- If a binary uses a large jump table, classify handlers first instead of reversing all of them one by one.
- When validation is a rolling recurrence like `acc = byte + C * acc`, try reversing it mathematically before reaching for brute force.

## 8) Personal Cheat Sheet (optional, but very useful)
- `file <binary>` -> Identify architecture, linking, stripping, and file type
- `readelf -W -d <binary>` -> See imports and dynamic linking info
- `strings -a -n 4 <binary>` -> Fast clue gathering, but treat embedded flags as suspicious
- `objdump -d -Mintel <binary>` -> Read `main`, handlers, and compare control-flow paths
- Function-pointer table in `main` -> Usually means dispatch logic worth mapping early
- Reversing pattern: if validation updates look like `acc = byte + base * acc`, try reversing with `% base` and integer division
