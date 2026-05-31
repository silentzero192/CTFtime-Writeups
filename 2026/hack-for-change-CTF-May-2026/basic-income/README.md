# Basic Income Crackme — Writeup

**Challenge**: Basic Income Crackme  
**Category**: Reverse Engineering  
**Flag**: `SDG{d957c4dd14d857a85f963058b867c101}`

---

## Overview

We are given a stripped, statically linked x86-64 ELF binary called `BasicIncome_Crackme`. Running it prompts for a 16-character household ID. If correct, it prints a voucher (the flag). If wrong, it says "Ineligible.".

```
$ ./BasicIncome_Crackme
BasicIncome eligibility calculator
household_id> AAAAAAAAAAAAAAAA
Ineligible.
```

The description hints that the correct input is derived from constants baked into the binary, not random — so the solution is to reverse engineer the validation logic and recover both the household ID and the flag.

---

## Initial Analysis

```
$ file BasicIncome_Crackme
BasicIncome_Crackme: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
statically linked, for GNU/Linux 3.2.0, stripped
```

Stripped and statically linked means no libc dependency info and no symbol names — but the `.rodata` section is intact and contains the strings and constants we need.

Running `strings` reveals the key strings:

```
BasicIncome eligibility calculator
Ineligible: household_id must be 16 characters.
household_id>
Ineligible.
Eligible. Voucher:
```

---

## Finding `main`

The entry point is at `0x401870` (from the ELF header). It calls `0x401680` which is clearly the `main` function — it prints the banner, prompts for input, reads it, validates, and either prints "Ineligible." or "Eligible. Voucher: ...".

Let's walk through the disassembly of `main` at `0x401680`.

### Setup and Input

```
401685: mov    $0x23,%edx            ; length 0x23 = "BasicIncome eligibility calculator\n"
40168a: mov    $0x1,%esi             ; stdout
40168f: mov    $0x47e008,%edi        ; string address
401698: mov    0xa9029(%rip),%rcx    ; FILE* stdout
4016bd: call   0x40acf0              ; fwrite
```

Then it prints the prompt `household_id> ` (at `0x47e061`), reads up to 0x50 bytes with `fgets` into a buffer at `rbx = rsp+0x30`, strips trailing newlines, and checks the length:

```
401742: cmp    $0x10,%rcx            ; must be exactly 16 bytes
401746: jne    0x401831              ; if not, print "Ineligible: ..." and exit
```

### Validation Loop

At `0x401780` begins the 16-byte verification:

```asm
401780: mov    %rax,%rdx              ; rdx = loop counter i
401783: and    $0x7,%edx              ; rdx = i & 7
401786: movzbl 0x47e0e0(%rdx),%edx    ; key_byte = data[0x47e0e0 + (i&7)]
40178d: xor    (%rbx,%rax,1),%dl      ; key_byte ^= input[i]
401790: cmp    %dl,0x47e0d0(%rax)     ; compare with expected[i]
401796: jne    0x401853               ; mismatch → print "Ineligible."
40179c: add    $0x1,%rax
4017a0: cmp    $0x10,%rax
4017a4: jne    0x401780
```

**In C, this is:**

```c
uint8_t expected[16] = { /* at 0x47e0d0 */ };
uint8_t key[8]        = { /* at 0x47e0e0 */ };

for (int i = 0; i < 16; i++) {
    if ((input[i] ^ key[i & 7]) != expected[i])
        goto ineligible;
}
```

So the correct household ID is derived by:

```
household_id[i] = expected[i] ^ key[i & 7]
```

### Flag Generation

If the ID is correct, execution falls through to `0x4017a6` where the flag is generated:

```asm
4017a8: mov    $0x29,%ecx            ; zero out 0x29 bytes
4017ad: mov    %rsp,%rdi
4017b3: rep stos %al,%es:(%rdi)      ; memset(output, 0, 0x29)

4017b5: xor    %eax,%eax             ; i = 0
4017c0: mov    %rax,%rdx
4017c3: and    $0xf,%edx             ; rdx = i & 0xf
4017c6: movzbl 0x30(%rsp,%rdx,1),%edx ; dl = household_id[i & 0xf]
4017cb: xor    0x47e0a0(%rax),%dl     ; dl ^= flag_mask[i]
4017d1: mov    %dl,(%rbx,%rax,1)      ; output[i] = dl
4017d4: add    $0x1,%rax
4017d8: cmp    $0x28,%rax             ; loop for 0x28 = 40 bytes
4017dc: jne    0x4017c0
```

Then it prints `"Eligible. Voucher: "` (`0x47e07d`) followed by the 40-byte output buffer.

**In C:**

```c
uint8_t flag_mask[40] = { /* at 0x47e0a0 */ };

for (int i = 0; i < 40; i++) {
    flag[i] = household_id[i & 0xf] ^ flag_mask[i];
}
printf("Eligible. Voucher: %s\n", output);
```

---

## Extracting the Constants

Using `xxd` to dump the relevant `.rodata` sections:

```
$ xxd -s $((0x7e0d0)) -l 16 BasicIncome_Crackme
3f c4 e5 a0 59 a5 0a cf 31 ce b7 f6 59 f3 06 92

$ xxd -s $((0x7e0e0)) -l 8 BasicIncome_Crackme  
09 fc d1 c6 6e c4 32 f6

$ xxd -s $((0x7e0a0)) -l 40 BasicIncome_Crackme
65 7c 73 1d 53 58 0d 0e 5b 06 02 54 06 03 50 5c
03 0f 55 5e 02 07 01 0f 0b 02 53 08 55 0f 02 53
55 09 04 57 4a 61 38 39
```

---

## Computing the Solution

```python
expected = bytes.fromhex('3fc4e5a059a50acf31ceb7f659f30692')
key      = bytes.fromhex('09fcd1c66ec432f6')
mask     = bytes.fromhex('657c731d53580d0e5b0602540603505c'
                          '030f555e0207010f0b025308550f0253'
                          '550904574a613839')

household_id = bytes(expected[i] ^ key[i & 7] for i in range(16))
flag = bytes(household_id[i & 0xf] ^ mask[i] for i in range(40))

print(f'household_id: {household_id.decode()}')
print(f'flag:         {flag.rstrip(b"\\x00").decode()}')
```

Output:

```
household_id: 684f7a8982f0774d
flag:         SDG{d957c4dd14d857a85f963058b867c101}
```

---

## Verification

Running the binary confirms the solution:

```
$ echo -n '684f7a8982f0774d' | ./BasicIncome_Crackme
BasicIncome eligibility calculator
household_id> Eligible. Voucher: SDG{d957c4dd14d857a85f963058b867c101}
```

**Flag: `SDG{d957c4dd14d857a85f963058b867c101}`**

---

## Summary

| Step | Address | What happens |
|---|---|---|
| Banner | `0x401685` | Print `"BasicIncome eligibility calculator"` |
| Prompt | `0x4016c2` | Print `"household_id> "` |
| Read | `0x4016f8` | `fgets(buf, 0x50, stdin)` |
| Check length | `0x401742` | Reject if not exactly 16 bytes |
| Validate | `0x401780` | XOR each byte with `key[i & 7]`, compare to `expected[i]` |
| Generate flag | `0x4017c0` | XOR household ID (repeating) with 40-byte `flag_mask` |
| Print | `0x4017de` | Print `"Eligible. Voucher: "` followed by the flag |

The binary uses three rodata tables:
- `0x47e0d0` — 16 expected XOR results
- `0x47e0e0` — 8-byte repeating XOR key
- `0x47e0a0` — 40-byte flag decoding mask

No obfuscation, packing, or anti-reverse — just a straightforward XOR crackme.
