# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

Challenge Name: Treasure Hunter  
Platform: Bearcat CTF 2026  
Category: Pwn  
Difficulty: Easy  
Time spent: ~30 minutes

## 1) Goal (What was the task?)
The binary asks for a pirate name and a treasure location, then prints a failure message unless you can redirect execution to a hidden `win` function.  
Success means triggering `win` with the correct arguments so it reads `flag.txt` and prints a flag in `BCCTF{...}` format.

## 2) Key Clues (What mattered?)
- `find_treasure()` uses `printf(buf)` directly after reading name input (`read(..., 10)`), which is a format string vulnerability.
- `find_treasure()` also reads `112` bytes into a `40`-byte stack buffer (`v2`), which is a stack overflow.
- `checksec` showed `Canary found` (so we need to leak/preserve canary).
- `checksec` showed `NX enabled` (no shellcode on stack).
- `checksec` showed `No PIE` (fixed code addresses; great for ROP).
- `win(a1, a2)` gives flag if `a1 == 6 || a2 == 7`.
- Useful gadget: `pop rdi; ret` at `0x40132d`.
- Useful gadget: `pop rsi; ret` at `0x40132f`.

## 3) Plan (Your first logical approach)
- First, confirm mitigations and function layout (`checksec`, `objdump`, `nm`).
- Use the format string bug to leak the stack canary so the overflow does not crash on stack check.
- Build a ROP chain in the second input to call `win(6, 0)`.
- Send exploit to remote service and capture printed flag.

## 4) Steps (Clean execution)
1. Action: Reviewed decompiled functions and disassembly.  
Result: Found both vulnerabilities in `find_treasure` (`printf(buf)` and oversized `read`).  
Decision: Use format string leak + overflow together.

2. Action: Determined format string offset by testing `%<n>$p`.  
Result: `%13$p` returned the canary value (ends with `00` as expected).  
Decision: Parse this leak and place it back in payload at canary slot.

3. Action: Calculated stack layout for overflow input (`v2` at `rbp-0x30`).  
Result: Offset to canary is `40` bytes, then `8` bytes saved `rbp`, then return address.  
Decision: Payload structure became:
`"A"*40 + canary + "B"*8 + ROP`.

4. Action: Built ROP chain using fixed addresses (no PIE).  
Result: Chain set registers and called hidden function:
`pop rdi; ret -> 6`, `pop rsi; ret -> 0`, `ret` (alignment), `win`.  
Decision: Send on second prompt (`Where do you think the treasure is?`).

5. Action: Ran against remote target `chal.bearcatctf.io 28799`.  
Result: Service printed the treasure flag.  
Decision: Challenge solved.

## 5) Solution Summary (What worked and why?)
The solve pattern was a classic vuln chaining approach: leak first, then control flow hijack.  
Because stack canary protection was enabled, a direct overflow would fail. The format string bug in the first input provided a reliable canary leak (`%13$p`). With the canary preserved, the second oversized `read` allowed a ROP chain that called `win` with valid arguments. Since PIE was disabled, gadget and function addresses were stable, making the exploit straightforward and reliable.

## 6) Flag
`BCCTF{rOp_cHaIn_hAs_BeEn_pWnEd}`

## 7) Lessons Learned (make it reusable)
- When you see both format string and overflow in one function, look for a leak-then-overwrite chain.
- Always run `checksec` early to decide between shellcode, ret2libc, or direct ret2win/ROP.
- Canary present does not block exploitation if any information leak exists.
- `No PIE` is a huge simplifier for beginners because gadget addresses stay constant.

## 8) Personal Cheat Sheet (optional, but very useful)
- `checksec --file=vuln` -> quick mitigation snapshot.
- `objdump -d -M intel vuln` -> verify offsets, stack frame, and gadgets.
- `nm -n vuln` -> list function symbols and addresses.
- Pattern: if there is `printf(user_input)`, immediately test `%p` leaks.
- Pattern: for overflow with canary, leak canary first, then reinsert exact value in payload.
