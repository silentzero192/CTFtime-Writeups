# TBA 2 - Writeup

## Challenge

- **Name:** `tba2`
- **Description:** `The announcement never aired. Only fragments survived. Some say the challenge is still To Be Announced`
- **Flag format:** `kashiCTF{...}`

## TL;DR

The binary is full of decoys:

- it is UPX-packed,
- it contains three fake flags in `.rodata`,
- it returns a fake-looking flag for incorrect input,
- it checks `TracerPid` and does a timing-based anti-analysis check,
- it validates a companion data blob before generating the real expected flag.

The cleanest solve is to let the binary do all the work and intercept the final `memcmp()` with `LD_PRELOAD`. By dumping the second buffer passed into `memcmp`, we recover the actual flag directly.

## Files

The challenge ships with two files:

```text
challenge_data.bin
prog
```

Quick recon:

```bash
file prog challenge_data.bin
```

Relevant result:

```text
prog: ELF 64-bit LSB pie executable, x86-64, ... statically linked, no section header
challenge_data.bin: data
```

And running the program without arguments:

```bash
./prog
```

prints:

```text
=== TBA-2 :: FINAL BROADCAST ===
Only one signal is true.
Usage: ./prog <candidate_flag>
```

Running it with a wrong input is the first hint that the challenge is intentionally misleading:

```bash
./prog test
```

Output:

```text
=== TBA-2 :: FINAL BROADCAST ===
Only one signal is true.
kashiCTF{TBA2_false_broadcast_B}
```

That string looks like a flag, but it is a decoy.

## Step 1: Unpack the Binary

`strings` on the original executable shows the UPX markers and several suspicious flag-like strings:

```bash
strings -a -n 4 prog | sed -n '1,220p'
```

Interesting artifacts:

- `UPX!`
- `kashiCTF{TBA2_false_broadcast_A}`
- `kashiCTF{TBA2_false_broadcast_B}`
- `kashiCTF{TBA2_false_broadcast_C}`
- `/proc/self/status`
- `TracerPid:`
- `challenge_data.bin`

So the first useful move is:

```bash
upx -d -o prog.unpacked prog
```

After unpacking, the binary becomes a normal dynamically linked ELF that is much easier to inspect.

## Step 2: Find the Real Control Flow

Disassembling the unpacked binary shows the important pieces.

### 2.1 Anti-debug check

Very early in `main`, the program opens `/proc/self/status`, scans for `TracerPid:`, and parses the number after it.

If `TracerPid != 0`, it flips into the fake path.

This is why normal `gdb`/`strace`-style debugging is annoying here.

### 2.2 Timing check

Right after that, the program measures two timestamps with `clock_gettime()` around a busy arithmetic loop.

If execution takes too long, it also flips into the fake path.

So there are two anti-analysis gates:

- debugger detection,
- slowdown detection.

### 2.3 Companion blob validation

Then the program opens `challenge_data.bin` and validates a small header plus the entire payload.

The header is:

```text
magic      = "TBA2DATA"
version    = 1
count      = 0x600
rec_size   = 0x34
hash       = 0x98ba2227b5b10bee
```

The file layout is:

- 0x40-byte header
- 0x13800-byte payload
- payload contains `0x600` records of size `0x34`

The payload is hashed with FNV-1a64, and the computed value must match the 64-bit value stored in the header. If this check fails, the binary again falls back into the fake path.

## Step 3: Hidden Bytecode in `.rodata`

There is another important blob in `.rodata`.

The code at `0x1337` decrypts a `0x43f`-byte region starting at `0x31e0` with a rolling single-byte XOR key. The decrypted bytes are not a plain string; they are a tiny bytecode program.

The VM supports a small instruction set:

- `1`: set register to immediate
- `2`: add immediate
- `3`: xor immediate
- `4`: multiply by immediate
- `5`: rotate-left
- `6`: move register
- `8`: modulo immediate
- `9`: emit output
- `10`: save register into one of 8 slots
- `11`: halt

When interpreted, the VM emits **24 indices** in the range `0..0x5ff`.

Those indices are later used to pick 24 records from `challenge_data.bin`.

## Step 4: Real Flag Construction

After the VM finishes, the program:

1. uses the 24 emitted indices to select 24 records,
2. mixes a set of 32-bit state values with those records,
3. runs another final mixing stage,
4. allocates `0x4b` bytes with `calloc`,
5. fills the first `0x4a` bytes with the generated expected flag,
6. checks `strlen(argv[1]) == 0x4a`,
7. compares the user input against the generated buffer with `memcmp`.

That last point is the important one:

```text
generated_flag_buffer <-> argv[1]
```

So the flag is present in memory in plain form immediately before the comparison.

## Step 5: Why `LD_PRELOAD` Is the Best Solve

At this point, there are two reasonable solve paths:

### Option A: Fully emulate the algorithm

This is possible, but it is more work:

- decrypt the bytecode program,
- emulate the VM,
- parse `challenge_data.bin`,
- reimplement the large record-mixing stage,
- reimplement the final PRNG-like output stage.

### Option B: Intercept `memcmp`

This is much cleaner.

The binary is dynamically linked after unpacking, and the final comparison uses libc `memcmp()`. If we preload our own `memcmp()` and log the second buffer whenever the comparison length is `0x4a`, the binary hands us the real flag itself.

This avoids:

- debugger attachment,
- fighting the anti-`TracerPid` logic,
- reimplementing the entire generator.

It also leaves the program logic intact: we are not patching the challenge, only observing the final comparison.

## Step 6: Solver Script

The included solver is [`solve.py`](./solve.py).

It automates the whole dynamic approach:

1. writes a temporary C source file implementing a hooked `memcmp()`,
2. compiles it into a shared object with `gcc`,
3. runs `prog` with `LD_PRELOAD`,
4. supplies a dummy 74-byte candidate string,
5. captures the real comparison buffer from `memcmp`,
6. decodes it into the flag,
7. optionally reruns the original binary with the recovered flag to verify it.

### Run it

```bash
python3 solve.py
```

Expected output:

```text
[*] Using binary: /path/to/tba2/prog
[*] Building preload hook and extracting the real comparison buffer...
[+] Recovered flag: kashiCTF{had_to_create_an_entire_new_challenge_but_it_w4s_rev_50_have_fun}
[*] Verifying the recovered flag against the original binary...
=== TBA-2 :: FINAL BROADCAST ===
Only one signal is true.
[broadcast] channel stabilized
kashiCTF{had_to_create_an_entire_new_challenge_but_it_w4s_rev_50_have_fun}
[+] Verification succeeded.
```

## Minimal Manual Hook

The core of the trick is just this idea:

```c
int memcmp(const void *lhs, const void *rhs, size_t len) {
    if (len == 0x4a) {
        dump(rhs, len);
    }
    return real_memcmp(lhs, rhs, len);
}
```

Because the binary uses:

```c
memcmp(argv[1], generated_flag, 0x4a);
```

we can simply dump `generated_flag`.

## Final Flag

```text
kashiCTF{had_to_create_an_entire_new_challenge_but_it_w4s_rev_50_have_fun}
```

## Notes

- The `false_broadcast_*` strings are decoys.
- A wrong input intentionally prints a fake flag.
- `TracerPid` plus the timing check are there to waste time if you go straight to an interactive debugger.
- The dynamic `memcmp` hook is the fastest reliable solve for this binary.
