# Treasure Chest - Writeup

## Challenge

- Name: `treasure chest`
- Description: `Score! You found a treasure chest! Now if only you could figure out how to unlock it... maybe there's a magic word?`
- Flag format: `RS{...}`

## Files

- `treasure` - stripped 64-bit ELF
- `solve.py` - full solver that recovers the flag and reproduces the binary's ciphertext check

## TL;DR

The binary reads user input, encrypts it with TEA using the hardcoded key `tiny_encrypt_key`, and compares the encrypted bytes against an embedded target buffer in `.data`.

Decrypting the embedded ciphertext gives the flag directly:

```text
RS{oh_its_a_TEAreasure_chest}
```

There is also a small bug in the binary: it pads with `len % 8` instead of `8 - (len % 8)`, then encrypts `len >> 2` 8-byte blocks, so it processes more memory than it actually requested. Because the first allocation comes from fresh zeroed heap memory, the comparison is still reproducible.

## Initial Recon

Running basic triage:

```bash
file treasure
strings -a -n 4 treasure
objdump -d -Mintel treasure
readelf -x .data treasure
```

Important observations:

- The binary is stripped.
- It imports `malloc`, `memcpy`, `memcmp`, `strlen`, `printf`, and `fgets`.
- Strings show a suspicious key-shaped value:

```text
tiny_enc
rypt_key
```

- `.data` contains a 34-byte target buffer at `0x404080`:

```text
38 75 5b cb 44 d2 be 5d 96 9c 56 43 ea 98 06 75
4a 48 13 e6 d4 e8 8e 4f 72 70 8b ff dc 99 f8 76
c5 c9
```

## Reversing The Important Functions

### 1. TEA block function at `0x4011c6`

The function at `0x4011c6` is standard TEA encryption on one 64-bit block:

- It loads two 32-bit words from an 8-byte block.
- It uses the TEA delta `0x9e3779b9`.
- It performs 32 rounds.
- It uses a 128-bit key split into four 32-bit words.

The key is built in `main` from two 64-bit immediates:

```c
"tiny_encrypt_key"
```

Split as little-endian 32-bit words:

```text
tiny | _enc | rypt | _key
```

### 2. Block loop at `0x4012a9`

This helper walks over the buffer and encrypts each 8-byte block in place.

Conceptually:

```c
for (i = 0; i < len >> 2; i++) {
    tea_encrypt_block(buf + i * 8, key);
}
```

This is already suspicious because an 8-byte block loop would normally use `len >> 3`, not `len >> 2`.

### 3. Main validation logic at `0x40131b`

The program:

1. Reads input with `fgets`
2. Removes the newline
3. Computes `len = strlen(input)`
4. Computes `remainder = len % 8`
5. Allocates `len + remainder` bytes
6. Copies the input
7. Zero-fills the extra `remainder` bytes
8. Encrypts the buffer
9. Compares the result with the 34-byte blob at `0x404080`

Pseudo-code:

```c
len = strlen(input);
remainder = len % 8;
buf = malloc(len + remainder);
memcpy(buf, input, len);
memset(buf + len, 0, remainder);
encrypt_blocks(buf, len + remainder, key);

if ((len + remainder) == 0x22 &&
    memcmp(buf, target, 0x22) == 0) {
    success();
}
```

## The Bug

There are two related mistakes:

### Wrong padding

To pad to an 8-byte boundary, the code should do:

```c
pad = (8 - (len % 8)) % 8;
```

But it actually does:

```c
pad = len % 8;
```

That means the accepted flag length must satisfy:

```text
len + (len % 8) = 34
```

The meaningful solution is:

```text
len = 29
```

### Wrong block count

The loop encrypts `len >> 2` 8-byte blocks instead of `len >> 3`.

For the accepted input:

- `len = 29`
- `pad = 5`
- total compared length = `34`
- encrypted blocks = `34 >> 2 = 8`

So the program touches 64 bytes of memory even though it only logically needed the first 34 bytes.

In practice, this still works because the first `malloc` returns a fresh chunk backed by zeroed heap memory, so the extra bytes are zero and the resulting ciphertext prefix is deterministic.

## Recovering The Flag

The easiest path is to decrypt the embedded ciphertext with TEA.

Target ciphertext:

```text
38755bcb44d2be5d969c5643ea9806754a4813e6d4e88e4f72708bffdc99f876c5c9
```

Decrypting the first four full 8-byte blocks with the key `tiny_encrypt_key` gives:

```text
Block 0: RS{oh_it
Block 1: s_a_TEAr
Block 2: easure_c
Block 3: hest}\x00\x00\x00
```

Concatenating and stripping the trailing zero padding yields the flag.

That already matches the challenge format and also satisfies the length equation:

```text
29 + (29 % 8) = 29 + 5 = 34
```

## Solver

`solve.py`:

- Implements TEA decryption
- Decrypts the embedded ciphertext
- Prints the recovered flag
- Reproduces the buggy encryption routine to prove the flag matches the binary's 34-byte comparison

Run it with:

```bash
python3 solve.py
```

Expected output:

```text
Flag: RS{oh_its_a_TEAreasure_chest}
Matches embedded ciphertext: True
```
