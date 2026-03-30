# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

**Challenge Name:** login  
**Platform:** VolgaCTF 2026 Quals  
**Category:** Pwn  
**Difficulty:** Hard  
**Time spent:** About 1 hour

## 1) Goal (What was the task?)
The goal was to analyze the provided challenge binary, exploit the remote service at `login-1.q.2026.volgactf.ru:45003`, and recover the flag. Success meant getting code execution or another file-read primitive on the server and extracting a flag in the format `VolgaCTF{...}`.

## 2) Key Clues (What mattered?)
- The file was a very small 32-bit static ELF named `vuln`.
- `checksec` showed `NX enabled`, `No canary`, and `No PIE`.
- The binary printed only `Enter the password:` and `Wrong password, please try again.`
- `main` reserved `0x40` bytes on the stack, but `read(0, buf, 0x80)` read 128 bytes into it.
- There were only a few visible functions: `_start`, `main`, `read_stdin`, and `write_stdout`.
- Hidden gadgets inside instruction bytes exposed `iretd` at `0x40000f` and `syscall` at `0x400010`.

## 3) Plan (Your first logical approach)
- Check the binary format and mitigations first to see whether this was a classic stack overflow or something more constrained.
- Disassemble the tiny code section to understand exactly how input was handled and whether there were reusable syscalls or gadgets.
- Search for unintended gadgets because the binary was too small for a normal ROP chain.
- If a useful mode-switch or syscall path existed, use the overflow to pivot into a more powerful second stage and spawn a shell on the remote service.

## 4) Steps (Clean execution)
1. **Action:** Ran basic triage with `file`, `checksec`, `readelf`, `objdump`, and `strings`.  
   **Result:** Confirmed the binary was a tiny 32-bit static ELF with a stack overflow, no canary, NX on, and fixed addresses.  
   **Decision:** Since direct shellcode would not work because of NX, I needed a ROP-style solution.

2. **Action:** Disassembled `main` carefully.  
   **Result:** `main` allocated `0x40` bytes on the stack and then called `read_stdin` with size `0x80`, giving a controlled stack overflow over saved `ebp` and the return address.  
   **Decision:** Use the overflow to control execution and build a staged payload.

3. **Action:** Checked the available gadgets with `ROPgadget`.  
   **Result:** The normal gadget set was tiny, but the raw instruction bytes contained a hidden `iretd` gadget at `0x40000f` and a hidden `syscall` at `0x400010`.  
   **Decision:** This suggested an unusual 32-bit to 64-bit transition instead of a standard i386-only chain.

4. **Action:** Reused the binary’s own `read_stdin` function as a first-stage primitive.  
   **Result:** I could overflow the stack, call `read_stdin` again, and place a larger second stage into the writable `.data` section at `0x40107c`.  
   **Decision:** Pivot the stack into `.data` with `leave; ret` so the second stage had more room.

5. **Action:** Built a second-stage chain that set `eax = 15`, used `leave; ret`, and then jumped through `iretd`.  
   **Result:** That transitioned execution so the hidden `syscall` gadget could be used together with an amd64 sigreturn frame.  
   **Decision:** Use SROP to fully control amd64 registers in one shot.

6. **Action:** Created an amd64 `SigreturnFrame` for `execve("/bin/sh", 0, 0)`.  
   **Result:** The frame set `rax = 59`, `rdi` to a `/bin/sh` string stored in `.data`, and `rip` back to the hidden `syscall` gadget.  
   **Decision:** Once this worked locally, use the same exploit remotely.

7. **Action:** Tested locally, then corrected one bug found with `strace`.  
   **Result:** My first version accidentally used syscall number `11`, which triggered `munmap` instead of `execve`. After changing `rax` to `59`, the payload spawned a shell successfully.  
   **Decision:** Run the final exploit against the remote host.

8. **Action:** Connected to `login-1.q.2026.volgactf.ru 45003` with the working exploit and searched for the flag file.  
   **Result:** I got a shell, listed `/app`, found `flag-0ef6e89817f10762af4036a33ba7e9b2.txt`, and read it.  
   **Decision:** Record the flag and save the exploit as `exploit.py`.

## 5) Solution Summary (What worked and why?)
The core pattern was a staged stack overflow in a tiny binary with almost no normal ROP surface. The first stage used the overflow to call the program’s own `read_stdin` function and place a larger payload into `.data`, then pivoted the stack there. The second stage used hidden `iretd` and `syscall` gadgets to switch into a 64-bit execution path and trigger amd64 SROP. That gave full register control, which made `execve("/bin/sh", 0, 0)` possible. Once a shell was spawned on the remote service, reading the flag file was straightforward.

## 6) Flag
`VolgaCTF{48406e1bf06999724172a17543f9e1d829a83144343d0681871e45489d35b902}`

## 7) Lessons Learned (make it reusable)
- Tiny binaries can still hide powerful gadgets inside instruction bytes, so it is worth checking unintended gadgets and not only named functions.
- When a normal ROP chain looks impossible, look for SROP opportunities, stack pivots, or cross-architecture transitions.
- `strace` is very useful for exploit debugging because it can reveal when a payload is almost correct but uses the wrong syscall number or arguments.
- Reusing the binary’s own `read` and `write` helpers is often the cleanest way to build a second stage in constrained pwn challenges.

## 8) Personal Cheat Sheet (optional, but very useful)
- `checksec --file=./vuln` -> quick mitigation overview.
- `objdump -d -Mintel ./vuln` -> inspect the real control flow and spot overflows.
- `ROPgadget --binary ./vuln` -> search both intended and unintended gadgets.
- `read@binary + stack pivot` -> useful pattern when the first payload is too small for the full exploit.
- `SROP` -> check this when you can reach `sigreturn` or set the syscall number to `rt_sigreturn`.
- `strace -f -o trace.txt python3 exploit.py` -> verify which syscall actually fired when the exploit nearly works.
