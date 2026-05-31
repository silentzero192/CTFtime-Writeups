# Spidr - Writeup

Writeup for GreyCTF Quals 2026 `spidr` (reversing).

## Challenge Files

- `chal`
- `spidr.png`

The PNG is just thematic flavor. The real work is in the ELF binary.

## Initial Recon

Running `file` and `checksec` on the binary shows:

- 64-bit PIE ELF
- dynamically linked
- not stripped
- full RELRO
- stack canary
- NX

The important part is that it is **not stripped**, so the function names are still present even though they are nonsense identifiers.

## What `main` Does

Disassembling `main` is enough to understand the top-level behavior:

1. Print `>> `
2. Read one `unsigned long long` with `scanf("%llu")`
3. Copy that input into a local variable
4. Pass a pointer to it into a function called `_Z5tjlfsPy`
5. Compare the transformed value against a fixed constant
6. If it matches, print `grey{%llu}`

The key comparison in `main` is:

```asm
movabs rax,0x67696d65666c6167
cmp    rdx,rax
```

So the binary is not checking a string directly. It is checking whether our input, after transformation, becomes:

```text
0x67696d65666c6167
```

## The Big Obfuscation Trick

Each helper function has the same structure:

- a local 32-bit "state" variable
- a long ladder of `cmp state, IMM`
- for each state, perform one of:
  - `value = constant + value`
  - `value = constant ^ value`
  - `value = constant * value`
- jump back into the dispatcher
- after about 99 arithmetic states, call the next helper

This repeats across **100 chained helper functions**.

So the whole binary is really just one giant deterministic transformation over a 64-bit integer.

## Why This Is Solvable

Every operation is invertible modulo `2^64`:

- `x -> x + c` is inverted by `x - c`
- `x -> x ^ c` is inverted by `x ^ c`
- `x -> x * c` is inverted by `x * c^{-1} mod 2^64`

All multiplication constants used by the binary are odd, so their modular inverses exist modulo `2^64`.

That means we do **not** need brute force, symbolic execution, or emulation. We only need to:

1. Parse the disassembly
2. Recover the exact ordered list of arithmetic operations
3. Start from the target constant
4. Apply every step in reverse

## Solver Strategy

`solve.py` automates the whole process:

1. Run `objdump -d -Mintel chal`
2. Split the output into named functions
3. Parse `main` to recover:
   - the first transform function
   - the final comparison target
4. Walk the helper chain function by function
5. Extract every arithmetic operation
6. Invert the chain from the end back to the start
7. Print the decimal input and the final flag

## Running The Solver

From this directory:

```bash
python3 solve.py chal
```

If the binary has execute permission and you also want a live check:

```bash
python3 solve.py chal --run
```

## Result

The recovered input is:

```text
4022823573008984730
```

## Flag

```text
grey{4022823573008984730}
```
