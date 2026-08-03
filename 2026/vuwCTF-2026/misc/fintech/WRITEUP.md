# fintech

**Category:** Misc
**Difficulty:** Easy/Medium
**Flag format:** `VuwCTF{...}`
**Description:**
> I needed to motivate my employees so I stole this presentation file from a rival company, but it's hard to understand.

## Files

| File          | Description                                        |
| ------------- | -------------------------------------------------- |
| `fintech.csv` | 33x101 grid of floating-point values               |

## tl;dr

The flag is hidden in the **exponents** of the values in the column right next to the
all-zero centre column of the CSV. Each value there is exactly `1E-(2*ascii)`, so
dividing the exponent by 2 and converting to a character recovers the flag:

```
VuwCTF{functions_never_give_up!!}
```

---

## Initial Analysis

We are given a single CSV file. Let's take a look at its shape and contents.

```
$ python3 -c "
import csv
rows = list(csv.reader(open('fintech.csv')))
print(len(rows), 'rows', len(rows[0]), 'cols')
"
33 rows 101 cols
```

The first rows look like this:

```
1.29247E-26,2.27438E-27,3.86141E-28,...,0,...,1.29247E-26
-6.01853E-36,-5.66163E-37,...,0,...,6.01853E-36
...
```

Every number is written in scientific notation and is **tiny** (between `1e-10` and
`1e-250`). The whole grid looks symmetric, and column 50 is all zeros.

### Structure of the grid

Let's examine the structure:

- **33 rows x 101 columns** (an odd width), so column index 50 is the centre.
- Column 50 is **all zeros** in every row — a vertical nodal line.
- The grid is symmetric left/right about that column.
- Rows are either all-positive or negative-on-the-left / positive-on-the-right.

Plotting the *sign* of each cell shows this clearly:

```
row 0  ++++++++++++++++++++++++++++++++++++++++++++++++++0++++++++++++++++++++++++++++++++++++++++++++++++++
row 1  --------------------------------------------------0++++++++++++++++++++++++++++++++++++++++++++++++++
...
```

The magnitude, when rendered as an image, looks like a smooth radially-symmetric
"blob" — a function that grows toward the corners of the grid. This is what makes the
file "hard to understand": the numbers look like a meaningless physics surface plot.

## Finding the Hidden Data

Since the whole thing is a big, seemingly-random numerical blob, let's look at the
individual values more carefully. A good spot to start is the column right next to the
strange all-zero centre column (column 49):

```
col 49: 1.00e-172  -1.00e-234  -1.00e-238  -1.00e-134  1.00e-168  ...
```

Unlike the surrounding columns, these values are **exact powers of 10** —
`1e-172`, `1e-234`, `1e-238`, ... That is not a coincidence.

If we list the exponents:

```
172, 234, 238, 134, 168, 140, 246, 204, ...
```

Every single one is **even**. Dividing by 2:

```
86, 117, 119, 67, 84, 70, 123, 102, ...
```

These are valid **ASCII character codes**! Converting them:

| exponent | /2 | ASCII |
|----------|----|-------|
| 172      | 86 | `V`    |
| 234      | 117| `u`    |
| 238      | 119| `w`    |
| 134      | 67 | `C`    |
| 168      | 84 | `T`    |
| 140      | 70 | `F`    |
| 246      | 123| `{`    |
| ...      | ...| ...    |

Reading all 33 rows gives the flag.

## Solution Script

```python
#!/usr/bin/env python3
import csv
import math

def solve(path: str = "fintech.csv") -> str:
    with open(path, newline="") as f:
        rows = [[float(x) for x in row] for row in csv.reader(f)]

    centre = len(rows[0]) // 2  # index of the all-zero centre column

    flag_chars = []
    for i in range(len(rows)):
        value = rows[i][centre - 1]
        exponent = -round(math.log10(abs(value)))
        flag_chars.append(chr(exponent // 2))

    return "".join(flag_chars)

if __name__ == "__main__":
    print(solve())
```

```
$ python3 solve.py
VuwCTF{functions_never_give_up!!}
```

## Flag

```
VuwCTF{functions_never_give_up!!}
```

## Key Takeaway

When a data file is "hard to understand", don't stare at the whole picture — look at
the **outliers and anomalies**. Here the dead giveaway was a column of exact powers
of 10 (with only even exponents) sitting right next to a column of literal zeros.
The message was hiding in plain sight in the exponents of scientific notation.
