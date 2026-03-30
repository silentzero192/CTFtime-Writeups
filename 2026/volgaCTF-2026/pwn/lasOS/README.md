# lasOS Writeup

Challenge Name: lasOS  
Platform: VolgaCTF 2026  
Category: Pwn  
Difficulty: Hard  
Time spent: Several hours

## 1) Goal (What was the task?)
The challenge gave a bootable OS image and a remote service that executes raw `x86_64` shellcode inside that custom OS. Success meant finding the real remote flag in the format `VolgaCTF{...}`.

## 2) Key Clues (What mattered?)
- The description explicitly said the challenge must be run on an Intel CPU with virtualization support.
- The main file was `image.bin`, which suggested a custom OS or bootable image rather than a normal userland binary.
- A `VolgaCTF{...}` string existed inside the handout, but the remote server rejected it.
- The service asked for raw machine code bytes, so the intended path was shellcode plus OS internals.
- The Intel-only note strongly hinted that some CPU-specific behavior would matter.

## 3) Plan (Your first logical approach)
- Check the image quickly for obvious strings and metadata to see whether the flag was embedded directly.
- Reverse the boot image and kernel to understand the syscall interface and exception handling.
- Look for a bug that behaves differently on Intel/KVM than on a generic emulator.
- Turn that bug into a minimal remote exploit and test it against the real service.

## 4) Steps (Clean execution)
1. I started with quick triage on `image.bin`.
   Action: Searched the image for strings and flag-looking data.
   Result: I found `VolgaCTF{w3ll_d0n3_n0w_d0_th1s_0n_r3m0t3}` inside the handout.
   Decision: Because the remote rejected it, I treated it as a placeholder and kept digging.

2. I extracted and disassembled the kernel from the disk image.
   Action: Used `dd` and `objdump` on the raw image.
   Result: I recovered the syscall behavior of the tiny OS.
   Decision: Focus on the syscall path, since the challenge runs our raw shellcode directly.

3. I mapped the important syscalls.
   Action: Reversed the syscall dispatcher and helper routines.
   Result: The key syscall was `syscall 3`, which copies a user-controlled register context into kernel memory and then returns with `sysretq`.
   Decision: A return path controlled by `sysretq` is a strong target for an Intel-specific bug.

4. I analyzed the `sysretq` fault behavior.
   Action: Forced a non-canonical return address in the saved context.
   Result: On Intel/KVM, `sysretq` raised a ring-0 `#GP` instead of cleanly returning to userland.
   Decision: Use that fault path to corrupt data that the exception handler reads immediately.

5. I mapped the `#GP` stack frame very carefully.
   Action: Tested many forged kernel `RSP` values against the remote service.
   Result: I found a safe lower range and a sharp upper boundary. `0xFFFFFF8000022100` turned out to be the useful value.
   Decision: Use that exact `RSP` because it places one controlled saved-register slot onto a live exception-table entry.

6. I found the final overwrite target.
   Action: Calculated where each pushed register lands during the `#GP` entry stub.
   Result: With `saved_rsp = 0xFFFFFF8000022100`, the saved `RDX` slot lands on `exception_table[13]`, which is the `#GP` string pointer used by the first `puts`.
   Decision: Write the flag pointer into saved `RDX`, trigger the fault, and let the kernel print the flag for me.

7. I tested the exploit against the remote service.
   Action: Ran the final shellcode through the live server and then updated `solve.py`.
   Result: The script printed the real remote flag.
   Decision: Finalize the exploit and keep the writeup focused on the working path.

## 5) Solution Summary (What worked and why?)
The main trick was not trusting the local flag-looking string in the handout. The real solve came from reversing the custom kernel, understanding that `syscall 3` restores a fully attacker-controlled context, and then abusing Intel's `sysretq` behavior with a non-canonical return address. That forced a kernel `#GP`, and by choosing the saved kernel `RSP` precisely, one controlled register slot overwrote the `#GP` exception-table entry with the flag pointer. The exception handler immediately called `puts` on that pointer, which printed the real remote flag.

## 6) Flag
`VolgaCTF{cf092d5238662faad02f25f2e4972bd6fff4cb63e9b4b3aa1ba9d51786635ae4}`

## 7) Lessons Learned (make it reusable)
- A flag-looking string inside a handout can be a decoy, especially when the challenge explicitly mentions remote testing.
- In kernel or OS pwn tasks, syscall handlers and exception handlers are usually the highest-value reverse-engineering targets.
- Intel/KVM behavior can differ from local emulation, so CPU-specific notes in challenge text are often part of the exploit.
- Precise frame layout work is more useful than blind brute force when the primitive is small and fragile.

## 8) Personal Cheat Sheet (optional, but very useful)
- `strings image.bin | rg VolgaCTF`
  Quick triage for obvious flag strings or hints.
- `dd if=image.bin of=/tmp/lasos_kernel.bin bs=1 skip=$((0xb400)) status=none`
  Extract the raw kernel blob from the boot image.
- `objdump -D -b binary -m i386:x86-64 --adjust-vma=0xffffff8000020000 /tmp/lasos_kernel.bin`
  Disassemble a raw high-half kernel image.
- `python3 solve.py --timeout 8`
  Run the final remote exploit.
- Pattern to remember: custom OS pwn challenge
  Check syscall dispatch, saved context layout, and exception printing paths early.
