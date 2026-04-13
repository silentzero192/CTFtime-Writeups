# Ghat Mirage - Writeup

## Challenge Info

- **Name**: `ghat mirage`
- **Description**: `The ghats of Kashi each glow, but only one is real. Find the true ghat, offer the correct mantra, and receive moksha.`
- **Attachment**: `prog` (provided locally here as `prog_f`)
- **Note**: `the binary may include decoy flags; find the true validator path.`

## TL;DR

The real flag is:

```text
kashi{Gh4t5_0f_K4sh1_Never_Di35}
```

The binary contains multiple fake success strings, but only one execution path reaches the actual validator.

## Initial Triage

The file was named `prog_f` locally:

```bash
file prog_f
```

Output:

```text
prog_f: ELF 64-bit LSB shared object, x86-64, statically linked, no section header
```

That is already suspicious:

- no section headers
- tiny file size
- strange strings
- packed appearance

Running `strings` immediately shows several tempting "flags":

```text
kashi{k4sh1_k1_g4l1y0n_m3in_kh0_j40}
kashi{m0ksh4_n0t_f0und_h3r3_try_4g41n}
kashi{fr4ke_g4ng4_0ffering_lol}
```

Because the challenge explicitly warns about decoys, none of these should be trusted.

## Unpacking the Binary

`strings` also reveals `UPX`, so the first real step is unpacking:

```bash
upx -d -o /tmp/prog_unpack prog_f
file /tmp/prog_unpack
```

After unpacking:

```text
/tmp/prog_unpack: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

Now normal reversing tools become useful again.

## Program Behavior

Running the binary without arguments gives:

```bash
./prog_f
```

```text
Usage: ./prog_f <pilgrim_offering>
```

So the program expects a single candidate string as input.

## Important Observation: Dispatcher Before Validation

Disassembling the unpacked file shows that `main` does not validate the input directly. Instead, it:

1. takes the provided argument
2. computes a hash using only the first 9 bytes
3. reduces it modulo `0xfb` (`251`)
4. jumps through a 251-entry function pointer table

The hash is FNV-1a:

```c
h = 0x811c9dc5;
for each byte in first_9_bytes:
    h ^= byte;
    h *= 0x1000193;
bucket = h % 251;
```

Most table entries point to fake success handlers.

## The Decoy Paths

The unpacked `.rodata` contains these strings:

```text
[JAI KASHI] Flag: kashi{k4sh1_k1_g4l1y0n_m3in_kh0_j40}
[JAI KASHI] Flag: kashi{m0ksh4_n0t_f0und_h3r3_try_4g41n}
[JAI KASHI] Flag: kashi{fr4ke_g4ng4_0ffering_lol}
```

Those are printed by short stub functions that simply call `puts()` and exit.

In the function table:

- bucket `0` points to one decoy
- bucket `1` points to another decoy
- almost every other bucket points to the third decoy

Only one bucket points to the real validator.

## The Real Bucket

One function pointer is overwritten with the real validator at runtime:

```text
table[9] = real_validator
```

So the only way to reach the true check is:

```text
FNV1a(first_9_bytes) % 251 == 9
```

That is useful later as a verification condition, but it is not the hard part.

## Real Validator Logic

The actual validator does this:

1. checks `strlen(input) == 32`
2. splits the input into 4 interleaved streams
3. folds each stream with base `0x83` (`131`)
4. compares the 4 resulting 64-bit values against constants

Equivalent pseudocode:

```c
if (strlen(s) != 32) fail();

uint64_t acc[4] = {0, 0, 0, 0};
acc[0] = s[0];

for (size_t i = 1; i < 32; i++) {
    int idx = i & 3;
    acc[idx] = acc[idx] * 131 + (unsigned char)s[i];
}

if (acc[0] != 0x00fd91b66d4b8b11) fail();
if (acc[1] != 0x00e661491544fdb8) fail();
if (acc[2] != 0x010fc69e6442ef55) fail();
if (acc[3] != 0x00f680346b31a222) fail();

success(s);
```

The nice part is that this is directly invertible.

## Why This Is Easy to Invert

Each accumulator is a base-131 number built from exactly 8 characters:

- `acc[0]` uses positions `0,4,8,12,16,20,24,28`
- `acc[1]` uses positions `1,5,9,13,17,21,25,29`
- `acc[2]` uses positions `2,6,10,14,18,22,26,30`
- `acc[3]` uses positions `3,7,11,15,19,23,27,31`

Because printable ASCII characters are all below `131`, each 64-bit constant can be expanded in base 131 to recover the original 8 characters exactly.

## Recovering the Four Character Streams

Using repeated division by `131` on the constants gives:

```text
acc[0] -> "ki404_ei"
acc[1] -> "a{tfsNr3"
acc[2] -> "sG5_he_5"
acc[3] -> "hh_K1vD}"
```

These are not read left-to-right as whole substrings. They must be interleaved back into the original 32-byte flag.

## Reconstructing the Flag

Interleaving the four recovered streams position-by-position yields:

```text
k a s h
i { G h
4 t 5 _
0 f _ K
4 s h 1
_ N e v
e r _ D
i 3 5 }
```

## Verification Script

Here is a compact Python script that reproduces the recovery:

```python
vals = [
    0x00fd91b66d4b8b11,
    0x00e661491544fdb8,
    0x010fc69e6442ef55,
    0x00f680346b31a222,
]

base = 131
cols = []

for v in vals:
    digits = []
    x = v
    for _ in range(8):
        digits.append(x % base)
        x //= base
    cols.append(digits[::-1])

flag = ["?"] * 32
for col, digits in enumerate(cols):
    for row, d in enumerate(digits):
        flag[row * 4 + col] = chr(d)

flag = "".join(flag)
print(flag)

h = 0x811C9DC5
for b in flag[:9].encode():
    h ^= b
    h = (h * 0x1000193) & 0xFFFFFFFF

print("bucket =", h % 251)
```

## Final Runtime Check

Testing the recovered flag against the unpacked binary:

```bash
/tmp/prog_unpack 'kashi{Gh4t5_0f_K4sh1_Never_Di35}'
```

Output:

```text
[JAI KASHI] Flag: kashi{Gh4t5_0f_K4sh1_Never_Di35}
```

This confirms:

- the candidate lands in the real dispatch bucket
- the true validator accepts it
- the printed value is not one of the planted decoys
