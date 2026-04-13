# Marauder Matchup - Writeup

> There's an opposing ship that just snuck up on us! They seem to have gotten a head start one before us. Can you find their pid and kill it before they do us in? We'll reward you handsomely.

## Challenge Files

- `arsenal`
- `solve.py`

## Overview

This challenge is a small **AArch64 VM** that reads:

1. A 4-byte constant count
2. That many 8-byte floating-point constants
3. A streamed bytecode program from `stdin`

The important opcodes are:

- `OP_CONSTANT`
- `OP_RETURN`
- `OP_SVC`
- `OP_POLL`
- `OP_EXEC_FILE`

The key observation is that `OP_SVC kill` does exactly what it sounds like: it pops a double from the VM stack, converts it to an integer PID, and calls `kill(pid, 9)`.

The challenge description gives the real trick:

> They seem to have gotten a head start one before us.

That hint is literal. The service runs in a fresh PID namespace, our process comes up as PID `4`, and the opposing process is the one started just before us: PID `3`.

So the solve is simply:

1. Push `3.0`
2. Call `OP_SVC kill`
3. Return cleanly

That immediately yields the flag.

## Recon

### File Type

```text
arsenal: ELF 64-bit LSB pie executable, ARM aarch64, static-pie linked, stripped
```

### Mitigations

```text
Arch:       aarch64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
```

This is another static AArch64 challenge binary, so most reversing is easier through:

- `strings`
- `readelf`
- Capstone disassembly from Python

## VM Identification

The low `.rodata` immediately gives away the instruction set:

```text
OP_CONSTANT
OP_RETURN
OP_POLL
OP_EXEC_FILE
OP_SVC           getpid
OP_SVC           kill
OP_SVC           print_arg
/tmp/%d
interpreting
```

That already tells us a lot:

- this is a custom bytecode VM
- it has built-in syscall-like services
- it creates or uses a path based on its PID

## Main Control Flow

The real `main` is at `0x8e00`.

High-level behavior:

```c
int main() {
    init_vm();

    while (read_program(&prog, 0) == 0) {
        global.current_program = &prog;
        interpret();
        free_program(&prog);
    }

    cleanup_vm();
    return 0;
}
```

Relevant disassembly:

```asm
0x8e68: bl  #0x9480      ; init
0x8e80: mov x0, x19
0x8e84: mov w1, #0
0x8e88: bl  #0x9740      ; read program from fd 0
0x8e8c: cbz w0, #0x8e70

0x8e70: str x19, [x20, #0x10]
0x8e74: bl  #0x91a4      ; interpret
0x8e78: mov x0, x19
0x8e7c: bl  #0x9870      ; free program
0x8e80: ...
```

So the challenge is not a normal “load full bytecode blob then run” design. It reads constants first, then streams opcodes live from the same file descriptor.

## Program Format

The parser at `0x9740` reads:

1. 4 bytes for the constant count
2. `count * 8` bytes for the constant array

Each constant is stored as an 8-byte `double`.

The bytecode itself is not buffered into a code array. The interpreter fetches it live from the current file descriptor via `0x9100`.

So a program looks like:

```text
u32 constant_count
double constants[constant_count]
u8 bytecode_stream[]
```

There is no explicit bytecode length. Execution ends when the VM sees `OP_RETURN`.

## VM Opcodes

From the interpreter at `0x91a4`, the opcode mapping is:

- `0` = `OP_CONSTANT`
- `1` = `OP_RETURN`
- `2` = `OP_SVC`
- `3` = `OP_POLL`
- `4` = `OP_EXEC_FILE`

### `OP_CONSTANT`

Format:

```text
00 <index>
```

Behavior:

- read one-byte constant index
- push `constants[index]` onto the VM stack

### `OP_RETURN`

Behavior:

- pop and print the top value
- print newline
- return to `main`

### `OP_SVC`

Format:

```text
02 <svc_id>
```

Service IDs:

- `0` = `getpid`
- `1` = `kill`
- `2` = `print_arg`

### `OP_POLL`

Polls the currently active file descriptor for readability.

### `OP_EXEC_FILE`

Opens a file path stored in global state and switches the interpreter to reading bytecode from that file descriptor.

## Global State and `/tmp/<pid>`

The init function at `0x9480` does three important things:

1. Initializes the VM stack
2. Gets the current PID
3. Formats `/tmp/%d` into a global buffer

Relevant disassembly:

```asm
0x94b0: add x0, x19, #0x20
0x94b4: str x0, [x19, #0x820]   ; stack top = stack base
0x94b8: bl  #0x22880            ; getpid
0x94c0: adrp x2, #0x69000
0x94c4: add x2, x2, #0xe58      ; "/tmp/%d"
0x94cc: add x0, x19, #0x830     ; path buffer
0x94d0: bl  #0xab80             ; snprintf(path, 0x40, "/tmp/%d", pid)
0x94dc: bl  #0x22ac0
```

The syscall wrapper at `0x22ac0` ORs the mode with `0x1000`, which is `S_IFIFO`, so this is creating a FIFO:

```c
mknodat(AT_FDCWD, path, mode | S_IFIFO, 0);
```

Cleanup later calls `unlinkat`, confirming the file is temporary.

So each process creates a named pipe like:

```text
/tmp/<pid>
```

This supports the challenge theme: ships communicating or attacking through their own PID-based channels.

## The Useful SVCs

### `getpid`

At `0x9378`:

```asm
0x9384: bl     #0x22880     ; getpid()
0x9388: scvtf  d30, w0
0x9390: ldr    x0, [x1, #0x820]
0x9394: str    d30, [x0], #8
```

This pushes the current process PID onto the VM stack as a floating-point value.

### `kill`

At `0x9438`:

```asm
0x9448: ldr    x1, [x0, #0x820]
0x944c: sub    x2, x1, #8
0x9450: ldur   d31, [x1, #-8]
0x9454: mov    w1, #9
0x945c: fcvtzs w0, d31
0x9460: bl     #0xa480
```

Translated:

```c
double arg = pop();
kill((int)arg, 9);
```

That is the whole win condition.

## Verifying the PID Hint

The description says:

> They seem to have gotten a head start one before us.

That suggests the enemy process is exactly one PID before ours.

To confirm, I used a small probe program:

```text
OP_SVC getpid
OP_SVC print_arg
OP_CONSTANT 0
OP_RETURN
```

with one constant `0.0` so the program can return cleanly.

The service output was:

```text
interpreting

0000 OP_SVC           getpid
        [ 4 ]
0002 OP_SVC           print_arg
4

0004 OP_CONSTANT         0 '0'
        [ 0 ]
0006 OP_RETURN
0
```

So our process PID is `4`.

Since the opponent was launched one before us, their PID is `3`.

## Why the Final Exploit Is One-Shot

The remote service closes after a program finishes, so there is no practical two-stage “probe then kill” solve on the same connection.

Fortunately:

- the PID namespace is stable
- our process is `4`
- the opponent is `3`

So the final exploit can be a single program that just kills PID `3`.

## Final Bytecode

Constants:

```python
[3.0, 0.0]
```

Bytecode:

```text
OP_CONSTANT 0
OP_SVC kill
OP_CONSTANT 1
OP_RETURN
```

In raw bytes:

```python
[
    0, 0,
    2, 1,
    0, 1,
    1,
]
```

The second constant `0.0` is only there so `OP_RETURN` has something harmless to print.

## Solve Script

The working script is [`solve.py`](./solve.py):

```python
from pwn import *
import re
import struct


HOST = "marauder.ctf.ritsec.club"
PORT = 1112

OP_CONSTANT = 0
OP_RETURN = 1
OP_SVC = 2

SVC_GETPID = 0
SVC_KILL = 1

OPPOSING_PID = 3


def pack_program(constants, bytecode):
    data = struct.pack("<I", len(constants))
    for value in constants:
        data += struct.pack("<d", value)
    data += bytes(bytecode)
    return data


def build_solve_program():
    return pack_program(
        [float(OPPOSING_PID), 0.0],
        [
            OP_CONSTANT, 0,
            OP_SVC, SVC_KILL,
            OP_CONSTANT, 1,
            OP_RETURN,
        ],
    )


def main():
    io = remote(HOST, PORT)
    io.send(build_solve_program())

    data = io.recvrepeat(3)
    text = data.decode("latin-1", errors="replace")
    print(text)

    match = re.search(r"RS\\{[^}\\n]+\\}", text)
    if match:
        log.success(f"flag: {match.group(0)}")


if __name__ == "__main__":
    main()
```

## Running the Exploit

```bash
python3 solve.py
```

Output:

```text
interpreting

0000 OP_CONSTANT         0 '3'
        [ 3 ]
0002 OP_SVC           kill

0004 OP_CONSTANT         1 '0'
        [ 0 ]
0006 OP_RETURN
0
RS{gr4pp1ing_m4r4ud3r5}
```

## Takeaways

- The most important clue was in the challenge description, not a deep memory corruption bug.
- The VM is intentionally small and very transparent once the opcodes are identified.
- `OP_SVC getpid` is there to help you reason about the process layout.
- The `/tmp/<pid>` FIFO setup is thematic and likely there to support the “ship-to-ship” interaction model, but the shortest solve is simply using the PID relationship and `kill`.
