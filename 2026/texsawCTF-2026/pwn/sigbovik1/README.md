# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

## Challenge Name:
Summer Trip

## Platform:
Texsaw CTF 2026

## Category:
Pwn

## Difficulty:
Hard

## Time spent:
About 3 hours

## 1) Goal (What was the task?)
The goal was to analyze a custom threaded-interpreter challenge, understand how its virtual machine worked, find a memory corruption bug, and use that bug to make the program reveal the flag. Success meant getting the remote service at `nc 143.198.163.4 1900` to print a flag in the format `texsaw{...}`.

This was not a normal buffer-overflow challenge with a simple stack smash. Instead, the target was a custom VM with its own instruction format, tagged values, closures, vectors, strings, linked lists, and function-call conventions. The real task was to move from “I can run bytecode in this VM” to “I can abuse a VM bug to escape the VM and execute the built-in win path.”

## 2) Key Clues (What mattered?)
- Challenge title: `summer trip`
- Description hint: `Do you like threaded interpreters?`
- Reference paper: `SCROP.pdf`
- Remote target: `nc 143.198.163.4 1900`
- Files provided locally:
  - `interpreter`
  - `compiler/`
  - `assembler/`
  - `SCROP.pdf`
- Important binary properties:
  - Static ELF
  - No PIE
  - NX enabled
  - RWX segment present
  - No stack canary
- Very important string clues inside the binary:
  - `flag.txt`
  - `/bin/cat`
  - `#<lambda free_vars=`
  - `arity=`
  - `offset=`
- Very important structural clue:
  - Each opcode mnemonic in the assembler mapped directly to a fixed virtual address like `.text.add`, `.text.vectorref`, `.text.call`, etc.

These clues strongly suggested this was a custom threaded interpreter where “opcodes” were really code pointers, and the SCROP paper hint suggested the intended path was probably control-flow abuse inside the interpreter rather than a classic native ROP chain from a plain C bug.

## 3) Plan (Your first logical approach)
- First, inspect the files to understand the full pipeline: source language -> compiler -> assembler -> interpreter.
- Next, reverse the VM semantics so I could understand stack layout, function calls, closures, vectors, and strings.
- Then, disassemble the binary handlers one by one and compare them against the compiler’s expected behavior to look for mismatches and unsafe memory access.
- Finally, turn the bug into a practical exploit by first reproducing the hidden win path locally, then using the same payload against the remote service.

## 4) Steps (Clean execution)

### 1. Inventory the challenge files
I started by listing the challenge files and identifying what each one did.

Important findings:
- `interpreter` was the actual target binary.
- `compiler/src/main.rs` compiled a Scheme-like language into VM assembly.
- `assembler/main.py` turned assembly mnemonics into 16-byte instructions.
- `SCROP.pdf` was a thematic hint toward exploitation in threaded interpreters.

This immediately told me the cleanest approach was not “fuzz the binary blindly,” but “learn the VM from source and then exploit it at the bytecode level.”

### 2. Check binary protections and metadata
I checked the ELF metadata and protections.

Key results:
- 64-bit static ELF
- No PIE
- NX enabled
- No canary
- RWX segment present

Why this mattered:
- No PIE meant all code addresses inside the binary were fixed.
- The binary being static made disassembly and address recovery easier.
- RWX and no PIE suggested control-flow redirection inside the VM could be enough to hit useful internal functions without building a full libc ROP chain.

### 3. Read the assembler and recover the instruction format
The assembler was extremely important because it revealed how the VM instruction stream was encoded.

Important observations:
- Every instruction was `16 bytes`: `8-byte opcode` + `8-byte immediate`
- `LOAD`, `GET`, `JUMP`, `CJUMP`, `LAMBDA`, and `PRIMAPPLY` all took immediates
- The “opcode values” were not small integers
- Example:
  - `ADD` -> `0x0ADD000`
  - `VECTORREF` -> `0x5ECE000`
  - `CALL` -> `0xCA11000`

That was a major clue: the opcodes were literally addresses of code sections inside the ELF. This matched the “threaded interpreter” hint perfectly.

### 4. Read the compiler to understand VM semantics
The Rust compiler source showed how the high-level language was lowered into bytecode.

Important things I learned:
- Values were tagged:
  - integers had the low 2 bits clear
  - pairs used one tag
  - vectors and strings used other tags
  - lambdas had their own tagged heap object
- The compiler emitted helper functions and higher-order utilities automatically
- Function calls used a VM stack discipline, not the native x86 stack in the usual way
- Closures stored:
  - code offset
  - free-variable vector
  - arity

This step mattered because I needed to know what a valid lambda looked like before I could corrupt one intentionally.

### 5. Disassemble the interpreter handlers
I dumped the custom opcode handlers from the ELF:

Useful sections included:
- `.text.vector`
- `.text.vectorref`
- `.text.vectorset`
- `.text.call`
- `.text.tailcall`
- `.text.lambda`
- `.text.return`
- `.text.done`

This gave me the real VM implementation, which was much more valuable than only reading the compiler.

Important discoveries:
- The interpreter stored its own VM stack in `rbx`
- It used `rsp` as an instruction pointer into the bytecode buffer
- `ret 8` advanced execution from one 16-byte instruction to the next
- `LAMBDA` created a heap object of three qwords:
  - offset
  - free-vars pointer
  - arity
- `CALL` used the lambda object to compute a new instruction pointer:
  - `rsp = bytecode_base + (lambda->offset << 4)`

This meant that if I could overwrite a lambda’s `offset`, I could redirect execution to any 16-byte-aligned “instruction” inside the user-controlled bytecode page.

### 6. Find the memory corruption bug
The core bug showed up in `vector-ref` and `vector-set!`.

Expected behavior:
- load the vector pointer
- read the vector length from `[vector]`
- compare user index against the length

Actual behavior:
- the code loaded the vector pointer into `rax`
- read the length into `rdi`
- then compared `rcx` against `rax` instead of `rdi`

In other words, it compared the index against the vector’s address, not its length.

That is a huge bug.

Why it is exploitable:
- vector addresses are large heap pointers
- normal user indexes are tiny integers
- so almost any positive index passes the bounds check
- `vector-ref` becomes an arbitrary read relative to the vector base
- `vector-set!` becomes an arbitrary write relative to the vector base

The same mistake existed in the string handlers too, but vectors were the easiest primitive to use for structured corruption.

### 7. Confirm the hidden win path existed
Before writing the exploit, I looked for signs of an existing “print the flag” function inside the binary.

Strings showed:
- `flag.txt`
- `/bin/cat`

Disassembly around the relevant function revealed an internal routine that called `execve("/bin/cat", ["cat", "flag.txt"], NULL)`.

That was perfect:
- I did not need shellcode
- I did not need libc
- I did not need to open/read the file manually
- I only needed to redirect execution to that built-in function

### 8. Build a minimal local bytecode runner
I first made sure I could execute simple hand-crafted bytecode successfully.

I tested tiny payloads such as:
- returning a constant
- calling a zero-argument lambda
- nesting calls

This was important because the full exploit depended on correct stack positioning inside the VM. A single wrong `FRAME`, `CALL`, or `RETURN` causes crashes immediately.

### 9. Understand why a simple control hijack was not enough
My first attempt redirected execution straight into the win function by forging an instruction entry.

That partially worked, but it crashed because:
- the fake native return stack ended up inside the read/execute bytecode page
- the win function prologue needed writable stack space

So the real problem became:
- not only “jump to the win function”
- but “jump to the win function with a safe writable stack”

This is where the threaded-interpreter structure really mattered.

### 10. Use the VM bug to create a safe fake execution context
The final exploit strategy was:

1. Create a real writable heap object under VM control.
2. Use out-of-bounds vector access to read the raw address of that object.
3. Use more out-of-bounds access to corrupt a lambda object.
4. Repoint the lambda’s code offset so `CALL` would jump into a fake instruction entry.
5. Overwrite part of the writable heap object so that the interpreter’s call machinery would use it as a safe stack frame.
6. Redirect control into the internal `execve("/bin/cat", ...)` helper.

The clever part was that I did not need an external gadget chain. I used the interpreter’s own object model and call machinery as the control-flow primitive.

### 11. Deal with ASLR without a separate external leak stage
Even though the binary itself was not PIE, heap and runtime data were still randomized.

I solved this by building the final payload so it computed what it needed at runtime:
- it leaked a live code-related value from the VM call stack
- it leaked a live heap object address with OOB vector access
- it used small arithmetic inside the VM to derive the right offset values

One nice trick I used:
- lambda arity is stored as a raw integer field
- by creating helper lambdas with chosen “arity” values derived from runtime values, I could reuse OOB `vector-ref` on lambda objects to effectively divide raw values by 4 and recover the exact bytecode offset I needed

That let the exploit stay self-contained and robust.

### 12. Verify locally
I then turned the final payload into a reusable exploit script:

- `python3 exploit.py build`
- `python3 exploit.py local`

Local verification result:
- the payload reliably reached the hidden `/bin/cat flag.txt` path
- the local run printed:

```text
cat: flag.txt: No such file or directory
```

That was expected, because there was no local `flag.txt` in the workspace. It still proved the exploit path itself was correct.

### 13. Test the remote service carefully
Before sending the final exploit, I tested the remote service with a tiny payload that should simply print `123`.

That was useful because it confirmed:
- the remote really was running the same interpreter logic
- the connection was working
- piping raw bytecode directly to the service was the correct delivery method

I found that using `nc` was the cleanest and most reliable way to talk to the service:

```bash
python3 exploit.py build test | nc 143.198.163.4 1900
```

### 14. Run the final payload against the remote target
Finally, I sent the exploit payload to the remote service:

```bash
python3 exploit.py build exploit | nc 143.198.163.4 1900
```

The service returned the flag:

```text
texsaw{ezpzlmnsqzy_didyoulikethepaper?_23948102938409}
```

## 5) Solution Summary (What worked and why?)
The challenge was a custom threaded interpreter where each opcode was actually a code pointer to a native handler in the ELF. By reversing the compiler and the VM handlers, I found that `vector-ref` and `vector-set!` had a broken bounds check: they compared the requested index against the vector pointer instead of the vector length. That turned them into powerful out-of-bounds read/write primitives.

From there, the successful exploit path was to corrupt a lambda object, because lambda calls directly control where the interpreter sets `rsp` inside the bytecode buffer. A simple jump into the win function was not enough by itself, so the final payload also created a writable fake execution context using heap-backed VM objects. After that, I redirected execution into the binary’s built-in `execve("/bin/cat", ["cat", "flag.txt"], NULL)` helper, which printed the remote flag.

## 6) Flag
`texsaw{ezpzlmnsqzy_didyoulikethepaper?_23948102938409}`

## 7) Lessons Learned (make it reusable)
- In custom VM and interpreter challenges, always read the compiler or assembler first if source is available. It gives structure much faster than blind disassembly.
- For threaded interpreters, opcode values themselves may be meaningful addresses. That can completely change the exploitation strategy.
- A “bad bounds check” in a VM object handler can be enough to escape the VM even if there is no classic stack overflow.
- When a binary already contains a win function, prefer steering execution there instead of building a more complicated shellcode or libc-based chain.
- For custom call conventions, validate tiny bytecode programs first. Small experiments save a lot of time before building the final exploit.

## 8) Personal Cheat Sheet (optional, but very useful)

### Commands
- `file interpreter`
  - Quick ELF identification
- `checksec --file=interpreter`
  - Check mitigation status
- `readelf -S interpreter`
  - See custom sections and their addresses
- `objdump -d -M intel -j .text.vectorref interpreter`
  - Disassemble a single VM handler cleanly
- `strings -a interpreter | rg 'flag|cat|lambda|arity|offset'`
  - Search for embedded win strings and useful hints
- `python3 exploit.py local`
  - Verify the exploit path locally
- `python3 exploit.py build exploit | nc 143.198.163.4 1900`
  - Send the final payload to the remote service

### Tools
- `objdump`
  - Best for handler-level reversing in stripped static binaries
- `readelf`
  - Best for understanding custom sections and fixed code addresses
- `rg`
  - Fast search through source and binary strings
- `checksec`
  - Fast security baseline
- `nc`
  - Very useful for raw binary payload delivery to remote services

### Patterns to remember
- Threaded interpreter:
  - Check whether opcode constants are real code addresses
- Custom VM:
  - Reconstruct tagged value format early
- Heap objects:
  - Lambda / closure structs are often great corruption targets
- OOB read/write:
  - Try to convert object corruption into a control-flow primitive instead of aiming directly for arbitrary native memory access
- Pwn with helper source:
  - Compiler + assembler + interpreter together often reveal the intended exploit path much faster than reversing only the binary
