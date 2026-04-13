# Impossible CP - Writeup

## Challenge Info

- **Category:** `Misc`
- **Name:** `impossible cp`
- **Description:** `This problem must be unsolvable, right?`
- **Files:**
  - `Problem-Statement.pdf`
  - `checker`
- **Remote:** `nc 34.126.223.46 18607`

## TL;DR

The PDF describes an interactive competitive-programming style problem that looks impossible: we must recover `A_n`, but we are not allowed to query index `n`.

The trick is that the hidden array is not arbitrary at all. The checker generates it using **MT19937**. Because the query `? i x` tells us whether `A_i & x` is zero, we can recover each observed value bit-by-bit by querying with `x = 1 << b`.

Since MT19937 outputs 32-bit values and its internal state size is **624 outputs**, recovering the first 624 values is enough to reconstruct the full PRNG state. After that, we can predict any future output, including the last hidden element.

This stays within the query limit because:

- We need `624 * 32 = 19968` bit queries.
- The statement guarantees `n >= 1000`.
- The allowed budget is `20n`, so the minimum budget is `20000`.

That leaves enough room to solve every case cleanly.

## Final Flag

```text
kashiCTF{d8b4ea850c6d4d34f74f66f60efd2904gBoy0bY97F}}
```

## Initial Analysis

The attachment is a single-page PDF describing this interaction:

```text
? i x
```

The response is:

- `0` if `A_i & x == 0`
- `1` otherwise

Important restrictions:

- `1 <= i <= n - 1`
- We cannot directly query `A_n`
- At most `20n` queries are allowed

At first glance this seems intentionally impossible, because:

- The array is not guaranteed to be a permutation
- We cannot touch the final element
- The statement frames the task like a hard information-theory puzzle

That immediately makes the checker more interesting than the statement.

## Inspecting the Files

Listing the provided files showed only the PDF and a stripped Rust binary:

```text
checker: ELF 64-bit LSB pie executable, x86-64, static-pie linked, stripped
```

Running `strings` on the checker exposed several very useful hints:

```text
src/main.rs
Well done, here's your flag:
/flag.txt
/.../mt19937-3.2.0/src/lib.rs
You ask too many questions.
```

The important observation is this path:

```text
.../mt19937-3.2.0/src/lib.rs
```

That is the whole challenge. Once we know the hidden sequence is generated from MT19937, the “impossible” problem becomes a standard PRNG state-recovery attack.

## Key Observation About the Query Primitive

The interaction gives us a yes/no answer for whether any selected bitmask overlaps with `A_i`.

If we choose:

```text
x = 1 << b
```

then:

```text
A_i & x != 0
```

means exactly:

```text
bit b of A_i is 1
```

So with 32 single-bit queries, we can reconstruct the full 32-bit value of any accessible element.

For index `i`, we do:

```text
? i 1
? i 2
? i 4
? i 8
...
? i 2147483648
```

and combine the returned bits into the exact 32-bit output.

## Why 624 Outputs Are Enough

MT19937 maintains an internal state of 624 32-bit words.

Each output value is the result of:

1. Taking one internal state word
2. Applying the MT tempering function

If we can observe 624 consecutive outputs, we can:

1. Reverse the tempering step on each output
2. Recover all 624 internal state words
3. Recreate the PRNG locally
4. Predict all future outputs

That means we do **not** need any clever reasoning about the array structure from the PDF. We only need enough observed elements to clone the PRNG.

## Query Budget Check

This part is important, because the attack only works if we stay under the checker limit.

To recover 624 values:

```text
624 values * 32 bits/value = 19968 queries
```

The challenge allows:

```text
20n queries
```

and the statement says:

```text
n >= 1000
```

So even at the smallest allowed size:

```text
20 * 1000 = 20000
```

which is still larger than `19968`.

So the challenge is solvable by design, but only if we realize the checker is driven by MT19937.

## Recovering the MT19937 State

MT19937 output is tempered using the well-known transformation:

```python
y ^= y >> 11
y ^= (y << 7) & 0x9D2C5680
y ^= (y << 15) & 0xEFC60000
y ^= y >> 18
```

To reconstruct the raw internal state, we reverse those operations in reverse order:

1. Undo `y ^= y >> 18`
2. Undo `y ^= (y << 15) & 0xEFC60000`
3. Undo `y ^= (y << 7) & 0x9D2C5680`
4. Undo `y ^= y >> 11`

Because the XOR dependencies move only one direction, each step can be inverted bit-by-bit.

## Solve Strategy

The full attack is:

1. Read `t`
2. For each test case, read `n`
3. Query the first 624 accessible indices
4. For each of those indices, query all 32 bit positions
5. Reconstruct the 624 exact 32-bit outputs
6. Untemper them into the MT19937 internal state
7. Rebuild the PRNG locally
8. Advance until reaching output number `n`
9. Send `! A_n`

Because the challenge only hides the last element, and all earlier indices are queryable, the first 624 outputs are enough to recover the entire generator.

## Local Verification

I first validated the approach against the provided `checker` binary.

One useful detail: solving locally returns a fake demonstration flag:

```text
Well done, here's your flag: flag{f4ke_flag_f0r_t0_5tring}
```

That confirmed the solve path before touching the remote instance.

## Solver Script

I wrote the solver in [solution.py](/home/jilani/Desktop/kashiCTF-2026/misc/impossible-cp/solution.py).

It supports both:

- `python3 solution.py local`
- `python3 solution.py remote`

### Core Ideas in the Script

The script does three main things:

#### 1. Recover outputs bit-by-bit

For each index `1..624`, it sends 32 queries:

```python
for i in range(1, N + 1):
    for mask in BIT_MASKS:
        query_blob.append(f"? {i} {mask}\n")
```

Each `1` response means that bit is set.

#### 2. Untemper the outputs

The recovered 32-bit numbers are converted back into raw MT state words using:

```python
def untemper(value: int) -> int:
    value = undo_right_xor(value, 18)
    value = undo_left_xor_mask(value, 15, 0xEFC60000)
    value = undo_left_xor_mask(value, 7, 0x9D2C5680)
    value = undo_right_xor(value, 11)
    return value & 0xFFFFFFFF
```

#### 3. Predict the final hidden value

Once the state is cloned, the script advances the generator until it reaches position `n`:

## Why This Challenge Is Nice

This is a great example of a challenge that looks like a CP impossibility puzzle but is really a reverse-engineering and PRNG-recovery problem.

The statement tries to push us toward algorithm design, but the binary tells the real story:

- the checker is a Rust program
- it contains `mt19937`
- the query primitive leaks exact bits
- the query limit is set just high enough for 624 full outputs

So the intended leap is not “find a clever combinatorial trick,” but:

> Recover the generator behind the array, then predict the forbidden value.

## Takeaways

- When a CTF challenge includes a custom checker, always inspect the checker before trusting the problem statement.
- A yes/no bitmask oracle is often enough to reconstruct full values.
- MT19937 is completely predictable after recovering 624 consecutive outputs.
- Query limits that look arbitrary are often chosen to fit an attack exactly.
