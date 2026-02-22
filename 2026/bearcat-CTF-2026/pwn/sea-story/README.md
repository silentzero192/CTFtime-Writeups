# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

Challenge Name: Sea Story  
Platform: Bearcat CTF 2026  
Category: Pwn  
Difficulty: Medium  
Time spent: ~35 minutes

## 1) Goal (What was the task?)
The task was to exploit a remote binary service at `chal.bearcatctf.io:40385` and make it reveal the challenge flag.  
Success meant obtaining output in the format `BCCTF{...}`.

## 2) Key Clues (What mattered?)
- The program asks for a menu option, then asks for your name.
- Symbol/function names were visible (`challenge`, `handlePirate`, `is_alphanum_string`), so reversing was straightforward.
- `checksec` showed an executable stack (`GNU_STACK` with execute permissions).
- In menu option `3`, argument order to `handlePirate` was wrong, causing user input to be called as a function pointer.
- Input validation used `strlen` + alphanumeric check, which can be bypassed with an early `\x00`.

## 3) Plan (Your first logical approach)
- Inspect binary protections and symbols first to identify likely exploit primitives.
- Reverse the menu logic and call chain to confirm whether user input can control execution flow.
- Design a payload that passes alphanumeric validation, then jumps to unrestricted shellcode bytes.
- Validate locally, then run the same exploit remotely to read `flag.txt`.

## 4) Steps (Clean execution)
1. Action: Ran `checksec`, `readelf`, and `objdump` on `vuln`.  
Result: PIE/canary present, but stack executable; symbols not stripped.  
Decision: Focused on control-flow misuse instead of ret2libc.

2. Action: Reversed `challenge()` and `handlePirate()`.  
Result: Option `3` calls `handlePirate(eatCoconut, name)` (swapped order). `handlePirate` does `call rdx`, so it executes `name` as code.  
Decision: Build direct shellcode execution payload.

3. Action: Studied input check (`strlen` + `is_alphanum_string`).  
Result: Only bytes before first `\x00` are validated as alphanumeric.  
Decision: Put alnum-only stage-0 stub before `\x00`, and raw shellcode after it.

4. Action: Built stage-0 stub `4Au0` (`xor al, 0x41; jnz +0x30`) plus padding, then appended amd64 `/bin/sh` shellcode.  
Result: Stub bytes are alphanumeric and reliably jump into unchecked shellcode region.  
Decision: Use this as final exploit payload.

5. Action: Sent menu option `3`, then payload as the name input, then shell commands (`cat flag.txt`).  
Result: Remote shell executed and printed the flag from `/app/flag.txt`.  
Decision: Save exploit as `solve.py` for repeatable solve.

## 5) Solution Summary (What worked and why?)
The solve worked because option `3` accidentally turned user input into executable code via a swapped function argument order. Even though input was filtered to alphanumeric, the filter was based on `strlen`, so a null byte ended validation early. That allowed a tiny alphanumeric jump stub up front and unrestricted shellcode bytes after the null. The shellcode spawned a shell and read the flag file.

## 6) Flag
`BCCTF{i_rEalLy_l1ke_sHeLcOde_go0d_joB}`

## 7) Lessons Learned (make it reusable)
- Always check function argument order in disassembly, especially around indirect calls.
- If input validation uses `strlen`, test null-byte truncation tricks immediately.
- `checksec` findings should guide exploit style early (e.g., executable stack suggests shellcode is viable).
- Validate exploit locally before remote; it saves time when debugging protocol issues.

## 8) Personal Cheat Sheet (optional, but very useful)
- `checksec ./vuln` -> Quick binary mitigation overview.
- `objdump -d -M intel vuln` -> Recover exact control flow and indirect call targets.
- `readelf -l vuln` -> Confirm stack execute permission (`GNU_STACK`).
- Pattern: If code uses `strlen` before validation, try an early `\x00` split payload.
