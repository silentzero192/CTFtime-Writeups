# Polaroid

> **Category:** Reversing  
> **Description:** This old polaroid won't develop. It needs a password, and the password is somewhere on the film.

## Challenge Overview

We are given a Mach-O 64-bit ARM64 executable (`polaroid`). The program prompts for a password and, if correct, decrypts an embedded encrypted image to produce `developed flag.png`.

## Analysis

### 1. Initial Reconnaissance

Running `strings` reveals several interesting strings:

```
usage: %s <password>
nope
flag.png
developed flag.png
```

Followed by a large block of seemingly random characters — the encrypted "film".

### 2. Disassembly

Using `capstone` to disassemble the `__text` section reveals the program's logic:

#### Password Check

The program:
1. Checks `argc == 2`
2. Checks the password length is **17** characters
3. Validates each character against hardcoded values:

```asm
0x1000004e4: ldrb   w8, [x19]       ; password[0]
0x1000004e8: cmp    w8, #0x65       ; 'e'
0x1000004f0: ldrb   w8, [x19, #1]   ; password[1]
0x1000004f4: cmp    w8, #0x78       ; 'x'
; ... continues for all 17 characters
```

The password bytes:

| Index | Hex   | Char  |
|-------|-------|-------|
| 0     | 0x65  | e     |
| 1     | 0x78  | x     |
| 2     | 0x70  | p     |
| 3     | 0x6f  | o     |
| 4     | 0x73  | s     |
| 5     | 0x65  | e     |
| 6     | 0x54  | T     |
| 7     | 0x68  | h     |
| 8     | 0x65  | e     |
| 9     | 0x4e  | N     |
| 10    | 0x65  | e     |
| 11    | 0x67  | g     |
| 12    | 0x61  | a     |
| 13    | 0x74  | t     |
| 14    | 0x69  | i     |
| 15    | 0x76  | v     |
| 16    | 0x65  | e     |

**Password: `exposeTheNegative`**

This is a photography reference — in film photography, "expose the negative" is the step where light hits the film to create the image.

#### Decryption Algorithm

Once the password is validated, the program:

1. Opens `flag.png` for writing
2. Loads 0x18b4 (6324) bytes of encrypted data from the `__const` section (the "film")
3. XORs each byte with a key byte derived from the password:

```python
for i in range(0x18b4):
    key_byte = password[i % 17]
    decrypted_byte = encrypted_byte ^ key_byte
    fputc(decrypted_byte, output_file)
```

The modulus calculation `i % 17` is implemented using a fast multiplication trick: `(i * 0xf0f1) >> 0x14` approximates `i / 17`.

#### The Film Reference

The encrypted data block is the "film" — an undeveloped Polaroid picture. The password is "on the film" in the sense that reverse engineering the binary reveals the password through the hardcoded character check.

### 3. Decryption

```python
password = b"exposeTheNegative"
enc_data = binary_data[0x720:0x720 + 0x18b4]
decrypted = bytes([enc_data[i] ^ password[i % len(password)] for i in range(len(enc_data))])
with open('flag.png', 'wb') as f:
    f.write(decrypted)
```

The decrypted data is a **700×140 PNG image** containing the flag.

## Flag

```
tjctf{...}
```
