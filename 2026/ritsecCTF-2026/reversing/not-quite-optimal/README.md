# Not Quite Optimal - Writeup

## Challenge Info

- **Name:** `not quite optimal`
- **Category:** `reversing`
- **File:** `not_quite_optimal`
- **Real flag format:** `RS{...}`

## TL;DR

This binary is a trap.

If you interact with it casually, it will happily print a fake `RITSEC{...}` flag stored directly in `.rodata`. The real clue is the required flag format: `RS{...}`. That tells us the visible `RITSEC{...}` string is a decoy.

The real path is:

1. answer `looking for the flag`
2. answer `please`
3. answer `PLEASE MAY I HAVE THE FLAG`

That last branch does **not** print the fake flag. Instead, it computes the real flag character by character using GMP and a deliberately slow tetration routine.

## First Look

Basic triage:

```bash
file not_quite_optimal
strings -a -n 3 not_quite_optimal
readelf -S -d not_quite_optimal
objdump -d -M intel not_quite_optimal > disasm.txt
```

`file` shows:

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

The interesting part from `strings` is that the binary is full of chatty text:

```text
<	haiiii what r u doin here?
<	oh okie... not sure i can be much help with that... good luck tho!!!
<	whoaaaa i know where to find that... say the magic word and ill get it for you
<	u rly should be more polite...
<	i couldnt hear u... could u try speaking a bit louder pls
<	meowmeow here u go... RITSEC{...}
<	waow i thought ud never ask... lemme go get it for you...
	that was exhausting, but there u are... mrrp meow
looking for the flag
please
PLEASE MAY I HAVE THE FLAG
```

Two things stand out immediately:

- it imports a bunch of GMP functions such as `__gmpz_mul`, `__gmpz_fdiv_ui`, `__gmpz_fdiv_q_2exp`
- it contains a full fake-looking flag string: `RITSEC{...}`

That second point is where the challenge tries to trick you.

## Why the Visible Flag Is Fake

The challenge expects flags in the format `RS{...}`, not `RITSEC{...}`.

So even before digging into the code, the embedded `RITSEC{...}` should be treated as suspicious. It is not hidden, not encoded, and not derived. It is just sitting in `.rodata` as bait.

That means the actual solve has to happen somewhere else in the code.

## Runtime Behavior

Running the binary gives a small dialogue:

```text
<	haiiii what r u doin here?
>	
```

The intended conversation is:

1. `looking for the flag`
2. `please`
3. `PLEASE MAY I HAVE THE FLAG`

If you miss the last exact uppercase phrase, the program goes down the fake-flag branch.

If you do type the exact uppercase phrase, it starts printing the real flag **very slowly**, one character at a time.

That slow-printing behavior is the reason for the challenge name: it is very much "not quite optimal".

## Main Control Flow

The main function starts at `0x1280`.

It uses three helpers worth naming:

- `0x18a0`: prints a string slowly with a fixed delay between characters
- `0x1950`: consumes characters until newline
- `0x1800`: computes a single output character for the real flag

### Stage 1

The first input check is done inline, not with `strcmp`.

Relevant snippet:

```asm
12d3: 48 ba 66 6f 72 20 74 68 65 20    movabs rdx,0x2065687420726f66
12dd: 48 33 54 24 08                   xor    rdx,QWORD PTR [rsp+0x8]
12e2: 48 b8 6c 6f 6f 6b 69 6e 67 20    movabs rax,0x20676e696b6f6f6c
12ec: 48 33 04 24                      xor    rax,QWORD PTR [rsp]
12f0: 48 09 c2                         or     rdx,rax
12f3: 75 0a                            jne    12ff
12f5: 81 7c 24 10 66 6c 61 67          cmp    DWORD PTR [rsp+0x10],0x67616c66
12fd: 74 3f                            je     133e
```

That is just a slightly fancy way to check:

```text
looking for the flag
```

### Stage 2

After the first correct answer, the program asks for the "magic word" and compares the second input against the string at `.rodata+0x226a`:

```asm
137b: lea rsi,[rip+0xee8]    # 226a
1385: call strcmp@plt
138f: jne 1464
```

That string is:

```text
please
```

If you do not say `please`, it prints:

```text
u rly should be more polite...
```

### Stage 3

If the second input is exactly `please`, the binary asks you to be louder, then checks a third string:

```asm
13c8: lea rsi,[rip+0xea2]    # 2271
13cf: mov rdi,rbp
13d2: call strcmp@plt
13d9: jne 1480
```

The target string at `.rodata+0x2271` is:

```text
PLEASE MAY I HAVE THE FLAG
```

This is where the trap splits:

- wrong third input: branch to `0x1480`, print the fake `RITSEC{...}` string
- correct third input: branch to `0x13df`, start computing the real flag

So the fake flag is not the reward for solving the challenge. It is the reward for taking the wrong branch.

## The Real Flag Loop

Once the correct dialogue path is followed, main enters this loop:

```asm
1428: 89 df                 mov    edi,ebx
142a: 83 c3 01              add    ebx,0x1
142d: e8 ce 03 00 00        call   1800
1432: 0f b6 f8              movzx  edi,al
1435: e8 26 fd ff ff        call   putchar@plt
1446: 83 fb 54              cmp    ebx,0x54
1449: 75 dd                 jne    1428
```

This tells us:

- the flag length is `0x54 = 84` characters
- each character is generated by the function at `0x1800`

## Why It Prints So Slowly

The helper at `0x1800` begins with:

```asm
181f: 69 c3 2c 01 00 00     imul   eax,ebx,0x12c
1840: 48 69 c0 40 42 0f 00  imul   rax,rax,0xf4240
184c: e8 9f f9 ff ff        call   nanosleep@plt
```

`0x12c = 300`, and `0xf4240 = 1,000,000`, so each character waits:

```text
index * 300 ms
```

before being printed.

Since the loop runs for 84 characters, the total runtime becomes huge:

```text
0.3 * (0 + 1 + 2 + ... + 83) seconds
= 0.3 * 3486
= 1045.8 seconds
= about 17.4 minutes
```

So even if you discover the right path dynamically, waiting for the full flag is intentionally annoying.

## Character Generation Routine

After the sleep, `0x1800` loads two `QWORD`s from a table in `.rodata`:

```asm
1859: lea    rax,[rip+0xa40]        # 22a0
1863: add    rax,rbx
1866: mov    rdx,QWORD PTR [rax+0x8]
186a: mov    rsi,QWORD PTR [rax]
186d: call   15f0
```

Because `rbx` was shifted left by 4 earlier, each table entry is 16 bytes:

```text
struct entry {
    uint64_t a;
    uint64_t h;
}
```

The table runs from `.rodata+0x22a0` to `.rodata+0x27df`, which is:

```text
(0x27e0 - 0x22a0) / 16 = 84 entries
```

Exactly one per output character.

## What Function `0x15f0` Does

This is the real math routine.

It uses GMP big integers and recursively computes:

```text
a ↑↑ h
```

where `↑↑` is **tetration**, meaning repeated exponentiation:

```text
a ↑↑ 1 = a
a ↑↑ 2 = a^a
a ↑↑ 3 = a^(a^a)
...
```

The routine handles several base cases:

- `h == 0` -> result `1`
- `h == 1` -> result `a`
- `a == 0` -> alternating edge-case handling
- `a == 1` -> result `1`

For the general case, it first recursively computes:

```text
exp = a ↑↑ (h - 1)
```

and then computes:

```text
a ^ exp
```

using standard binary exponentiation with GMP:

```asm
16c1: mov    esi,0x1
16c6: mov    rdi,r12
16c9: call   __gmpz_set_ui@plt     ; out = 1

16d6: test   BYTE PTR [rax],0x1
16de: jne    1770                  ; if exponent bit is set, out *= base

16ef: call   __gmpz_fdiv_q_2exp@plt ; exponent >>= 1
1788: call   __gmpz_mul@plt         ; base *= base
```

At the end, it does:

```asm
171e: mov    esi,0x100
1726: call   __gmpz_fdiv_ui@plt     ; result mod 256
172b: add    rax,0x1
172f: shr    rax,1
```

So the final character is:

```text
char = ((a ↑↑ h) mod 256 + 1) / 2
```

That is the key observation.

## The Table

The first few entries are:

```text
(706619, 2)
(1649525, 2)
(3315141, 2)
(3672983, 2)
...
```

The last few are:

```text
(18252019, 9359719)
(19350313, 9850159)
(20839305, 10402185)
(21715701, 10616502)
(22340793, 11301289)
```

Those later heights are enormous, so computing exact tetration values is impossible in normal integer arithmetic.

But we do **not** need the full integer.

We only need:

```text
(a ↑↑ h) mod 256
```

## The Number Theory Shortcut

Because the modulus is only `256 = 2^8`, and all bases in the real table are odd, we can evaluate the tetration tower modulo powers of two recursively.

For odd `a` and `k >= 3`:

```text
a^x mod 2^k
```

depends on the exponent modulo:

```text
lambda(2^k) = 2^(k-2)
```

That lets us compute the top-level result mod `2^8` by recursively computing smaller-modulus exponents.

In practice, this short recurrence is enough:

```python
def tetmod_pow2_odd(a, h, k):
    if k == 0:
        return 0
    if h == 1:
        return a % (1 << k)
    if k == 1:
        return 1
    if k == 2:
        e = tetmod_pow2_odd(a, h - 1, 1)
        return pow(a, e, 4)
    e = tetmod_pow2_odd(a, h - 1, k - 2)
    return pow(a, e, 1 << k)
```

Then each character is:

```python
r = tetmod_pow2_odd(a, h, 8)
ch = (r + 1) // 2
```

## Solver Script

This script reads the table directly from the binary and reconstructs the full flag:

```python
from pathlib import Path
import struct

data = Path("not_quite_optimal").read_bytes()

def tetmod_pow2_odd(a, h, k):
    if k == 0:
        return 0
    if h == 1:
        return a % (1 << k)
    if k == 1:
        return 1
    if k == 2:
        e = tetmod_pow2_odd(a, h - 1, 1)
        return pow(a, e, 4)
    e = tetmod_pow2_odd(a, h - 1, k - 2)
    return pow(a, e, 1 << k)

chars = []
for off in range(0x22A0, 0x27E0, 16):
    a = struct.unpack_from("<Q", data, off)[0]
    h = struct.unpack_from("<Q", data, off + 8)[0]
    r = tetmod_pow2_odd(a, h, 8)
    chars.append(chr((r + 1) // 2))

print("".join(chars))
```

## Sanity Check

A few decoded characters line up cleanly:

```text
entry 0  -> 'R'
entry 1  -> 'S'
entry 2  -> '{'
...
last entry -> '}'
```

So the recovered output is consistent with the expected flag format from end to end.

## Final Flag

```text
RS{4_littl3_bi7_0f_numb3r_th30ry_n3v3r_hur7_4ny0n3_19b3369a25c78095689a38f81aa3f5e3}
```

## Takeaways

- Always trust the **required flag format** more than a suspicious string in `.rodata`.
- If a binary imports GMP, expect big integer math instead of simple hashing or string compares.
- When a challenge computes huge numbers but only uses a tiny modulus, modular arithmetic is often the intended shortcut.
- The fake flag and the intentionally slow output are both part of the challenge design.
