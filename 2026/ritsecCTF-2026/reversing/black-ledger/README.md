# Black Ledger Writeup

`black_ledger` is a stripped AArch64 ELF that asks for a 32-rune “course” and prints a flag if the course is correct.

## Challenge summary

At a high level the binary does three things:

1. It reads exactly 32 bytes.
2. It runs the first 16 bytes through a 10-round custom block transform.
3. It runs the last 16 bytes through a custom VM with 505 decoded instructions.

If both halves match the embedded targets, the program enters a final decoding routine that prints the flag.

This writeup walks through each stage and shows how to solve the binary statically.

## Files

The directory only contains the stripped binary:

```text
black_ledger
```

`file black_ledger`:

```text
ELF 64-bit LSB executable, ARM aarch64, dynamically linked, stripped
```

That matters because:

- We cannot run it natively on an x86 host without emulation.
- There are no symbols.
- The solve has to come from static analysis and targeted emulation/reimplementation.

## Initial triage

Useful strings:

- `The Black Ledger waits below deck.`
- `Speak the captain's 32-rune course.`
- `The tide rejects that course.`
- `The ledger stays locked.`

The binary also contains a fake 32-byte decoy string:

```text
zo21_parrot_loot_fake_way_out_xx
```

The program rejects that string explicitly, so it is just there to waste time.

## Main structure

`main` does roughly this:

1. Read input with `fgets`.
2. Strip the trailing newline with `strcspn`.
3. Require length `== 0x20`.
4. Reject the decoy string.
5. Transform bytes `0..15`.
6. Transform bytes `16..31`.
7. Compare both results against constants in `.rodata`.
8. If both match, decode and print the flag.

The interesting part is that the first half and second half use completely different machinery.

## Part 1: first 16 bytes

### The helper at `0x400f80`

The front half uses a helper function at `0x400f80`.

There is also a byte-substitution helper at `0x400f40` that applies a 256-byte S-box to all four bytes of a 32-bit word.

The helper at `0x400f80` uses:

- S-box 1 at `0x4010e0`
- S-box 2 at `0x4011e0`
- Two 32-bit round constants
- Five round bytes controlling rotations

Rewritten in Python:

```python
def F(inp, k1, k2, bs):
    x = sbox_word(rol32(inp ^ k1, bs[0]), sbox1)
    x = (x + k2) & 0xffffffff
    y = rol32(k1, bs[2]) ^ x ^ rol32(x, bs[1])
    y = sbox_word(y, sbox2)
    z = (rol32(k2, bs[3]) + y) & 0xffffffff
    return rol32(z, bs[4]) ^ z
```

### Round structure

The binary treats the first 16 bytes as four little-endian `uint32_t`s:

```text
A, B, C, D
```

For each of 10 rounds:

```python
U = F(C, rk0, rk2, rb0_4) ^ A
V = F(D, rk1, rk3, rb5_9) ^ B
```

Then it permutes the state differently depending on round parity:

```python
if round_is_even:
    A, B, C, D = C, D, U, V
else:
    A, B, C, D = D, C, V, U
```

The round constants live at:

- `0x4013c0` for the 40 dwords
- `0x401460` for the 100 round bytes

### Target for the first half

The final 16-byte result is compared against the qword at `0x402710`:

```text
f6 76 16 48 63 41 b8 82 59 4c d3 de 76 2a 0b 26
```

As little-endian dwords:

```text
0x481676f6
0x82b84163
0xded34c59
0x260b2a76
```

### Reversing the first half

The nice part is that the round update is directly invertible once the helper is known.

For an even round:

```text
(A', B', C', D') = (C, D, U, V)
```

So:

```text
C = A'
D = B'
A = C' ^ F(C, rk0, rk2, rb0_4)
B = D' ^ F(D, rk1, rk3, rb5_9)
```

For an odd round:

```text
(A', B', C', D') = (D, C, V, U)
```

So:

```text
D = A'
C = B'
A = D' ^ F(C, rk0, rk2, rb0_4)
B = C' ^ F(D, rk1, rk3, rb5_9)
```

Walking backward from the target recovers the first 16 bytes:

```text
blacktidechartsm
```

## Part 2: last 16 bytes

### The VM

The second half initializes an 8-word state:

```text
R0..R3 = input words 4..7
R4..R7 = 0
```

Then it decodes a program stream out of the qwords at `0x4016d0`.

The decode is stateful and depends on a rolling 32-bit value `w12`. The raw decoded 8-byte instruction format is:

- byte 0: opcode
- byte 1: destination register
- byte 2: source register
- byte 3: rotate count
- bytes 4..7: immediate

The mask for decoding comes from `0x402700`.

### Opcode mapping

The jump table at `0x4010d0` reveals the real meaning of opcodes `1..11`:

```text
1  -> XORR
2  -> ADDR
3  -> ROL
4  -> SBOX1
5  -> MIX1
6  -> SWAP
7  -> XORI
8  -> ADDI
9  -> MULI
10 -> MIX2
11 -> SBOX2
0  -> MOVI
255 -> END
```

That opcode order is the important detail. If you assume `1 -> MULI`, the VM model breaks almost immediately.

### Decoded operations

The decoded stream contains:

- 4 `MOVI` instructions up front, which fully define `R4..R7`
- 500 ordinary instructions after that
- 1 `END`

Counts by kind:

```text
XORI  = 112
ROL   = 112
MIX2  = 56
MIX1  = 56
SBOX1 = 37
SWAP  = 33
ADDR  = 28
SBOX2 = 22
MULI  = 16
XORR  = 14
ADDI  = 14
MOVI  = 4
END   = 1
```

### Target for the second half

The final VM state is compared against:

At `0x402720`:

```text
31 b2 f9 61 5f 94 ae 1f 3c 1e 9a 64 16 21 3c ff
```

At `0x402730`:

```text
30 b4 48 d4 9f 0d 4b 70 e0 45 0e 72 cb 30 56 c6
```

As little-endian words:

```text
0x61f9b231
0x1fae945f
0x649a1e3c
0xff3c2116
0xd448b430
0x704b0d9f
0x720e45e0
0xc65630cb
```

### Reversing the VM

Because the first four instructions are `MOVI R4..R7`, the initial unknowns only live in `R0..R3`.

So we can reverse from the target state all the way back to the state immediately after those four `MOVI`s.

Each instruction is inverted directly:

- `XORR`: `R[a] ^= R[c]`
- `ADDR`: `R[a] -= R[c]`
- `ROL`: `R[a] = ror(R[a], r)`
- `SBOX1`: inverse S-box, then xor immediate
- `MIX1`: subtract immediate, xor rotated source
- `SWAP`: swap again
- `XORI`: xor immediate
- `ADDI`: subtract immediate
- `MULI`: multiply by modular inverse of `(imm | 1)` mod `2^32`
- `MIX2`: `ror(R[a] ^ imm, r) - R[c]`
- `SBOX2`: inverse S-box after undoing the rotate/add/xor layer

That recovers the back half as:

```text
utinyroutes1701!
```

## Final input

Combining both halves gives the full 32-byte course:

```text
blacktidechartsmutinyroutes1701!
```

## Recovering the flag

Passing both checks does not print the flag directly from a constant string.

Instead, the success path at `0x400c40`:

1. Mixes the recovered input with the front-half target words.
2. Mixes in the final VM state words.
3. Runs a 12-step state update using the VM S-box at `0x4015d0`.
4. Generates 27 bytes of keystream-like output.
5. XORs the first 16 bytes with the block at `0x402740`.
6. XORs the remaining bytes with bytes starting at `0x4026d0 + 0x10`.

## Solver

The included [solve.py](./solve.py) is dependency-free and works directly from the local ELF bytes.

It:

- Rebuilds the front-half helper from the embedded tables
- Reverses the 10-round first-half transform
- Decodes the VM program stream
- Reverses the VM state to recover the last 16 bytes
- Reimplements the success path to recover the flag

Run it with:

```bash
python3 solve.py
```

Expected output:

```text
course: blacktidechartsmutinyroutes1701!
flag:   RS{d34d_r3v_t311_n0_tal35}
```

## Takeaways

- Small decode mistakes matter. The VM opcode order looked plausible in more than one arrangement, but only the jump-table-derived mapping was correct.
- The binary intentionally splits the problem into two different reverse tasks: a custom round function and a custom VM.
- The final flag is not just “stored somewhere”. Even after recovering the course, there is another decoding layer that has to be understood or emulated.
