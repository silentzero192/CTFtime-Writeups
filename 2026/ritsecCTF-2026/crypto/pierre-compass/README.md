# Pierre Compass

## Challenge Info

- **Name**: `pierre compass`
- **Category**: `crypto`

## Files

The challenge only gives one file:

- `params.txt`

Its contents provide:

- a shuffled alphabet of length `94`
- three moduli: `m1 = 95`, `m2 = 37`, `m3 = 19`
- three seeds: `s1 = 11`, `s2 = 29`, `s3 = 7`

## Key Observation

The title is the main clue here: `pierre` strongly suggests **Pierre L'Ecuyer**, who is known for combined linear congruential generators.

A classic L'Ecuyer-style combined generator uses multiple LCG outputs and combines them with an alternating sum, commonly in the form:

```text
z_n = (x1_n - x2_n + x3_n) mod (m1 - 1)
```

That matches this challenge unusually well because:

- `m1 - 1 = 94`
- the provided alphabet length is also `94`

So the combined output can be used directly as an index into the alphabet.

## What Was Missing

The file gives us:

- the moduli
- the seeds
- the alphabet

But it does **not** give the LCG multipliers.

Because the parameter sizes are tiny, we can brute-force the multiplier triple:

```text
x1_{n+1} = (a1 * x1_n) mod m1
x2_{n+1} = (a2 * x2_n) mod m2
x3_{n+1} = (a3 * x3_n) mod m3
```

We only test multipliers coprime to their moduli, since otherwise the generators collapse immediately.

Then for each candidate triple `(a1, a2, a3)` we:

1. advance the three generators
2. compute `(x1 - x2 + x3) mod 94`
3. use that value as an index into the shuffled alphabet
4. build the resulting stream until the state repeats
5. search the stream for a flag-shaped token `RS{...}`

## Solving

Brute forcing the multiplier space gives one clean candidate whose stream starts with a flag:

The winning multipliers are:

```text
a1 = 69
a2 = 30
a3 = 2
```

## Why This Interpretation Is Credible

- The challenge title points directly at L'Ecuyer.
- The combination modulus `m1 - 1 = 94` matches the alphabet length exactly.
- A naive additive-LCG interpretation does not produce a flag.
- The multiplicative combined-generator interpretation does.
- Among the hits, the intended one is the only clean candidate that begins with a flag immediately.

## Final Flag

```text
RS{trU1y_ch40TiC}
```
