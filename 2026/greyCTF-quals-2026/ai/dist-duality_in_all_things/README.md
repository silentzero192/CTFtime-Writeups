# Duality in All Things - Writeup

> **Category:** `AI`   
> **Flag:** `grey{du4l_0pt1m1z4t10n_l3ft_th3_supp0rt_v3ct0rs_b3h1nd}`

> *Where there is Yin, there is Yang.*  
> *Where there is a primal problem, there is a dual problem.*  
> *Where there is regularization, there are oversteppers.*  
> *Where there are oversteppers, there is slack.*  
> *I wonder: Where there is a challenge, is there a flag?*

---

## Description

We are given three files:

| File | Purpose |
|------|---------|
| `svc_dual_params.pkl` | Pickled sklearn `SVC` dual parameters — support vectors, dual coefficients, intercept, and regularization constant `C` |
| `verify.py` | Checks whether a candidate string's SHA256 matches the expected hash |
| `requirements.txt` | Dependencies: `numpy`, `scikit-learn` |

The challenge is to recover the flag string from the SVM dual parameters.

---

## Background: SVM Duality Primer

A Support Vector Machine solves two equivalent optimization problems:

**Primal (hinge loss + regularization):**
```
min ½‖w‖² + C · Σ ξᵢ
s.t. yᵢ(w·xᵢ + b) ≥ 1 - ξᵢ,  ξᵢ ≥ 0
```

**Dual (Lagrange multipliers):**
```
max Σ αᵢ - ½ Σ Σ αᵢαⱼyᵢyⱼxᵢ·xⱼ
s.t. 0 ≤ αᵢ ≤ C,  Σ αᵢyᵢ = 0
```

Key quantities in the pickle:
- `C = 0.05` — regularization strength (small → heavy regularization, wide margin)
- `dual_coef_` — stores `αᵢ · yᵢ` for each support vector
- `support_vectors_` — the data points that are support vectors (554 of them, 12-dimensional)
- `intercept_` — the bias term `b` (≈ 0 here)

The **slack variables** `ξᵢ = max(0, 1 - yᵢ · f(xᵢ))` measure how far a point is on the wrong side of the margin. When `αᵢ = C`, the point has slack (`ξᵢ > 0`); when `0 < αᵢ < C`, it lies exactly on the margin (`ξᵢ = 0`).

---

## Analysis

### 1. Inspecting the model

```python
import pickle
import numpy as np

with open('svc_dual_params.pkl', 'rb') as f:
    data = pickle.load(f)

print(f"C = {data.C}")
print(f"dual_coef_ shape: {data.dual_coef_.shape}")
print(f"support_vectors_ shape: {data.support_vectors_.shape}")
print(f"intercept_: {data.intercept_}")
```

Output:
```
C = 0.05
dual_coef_ shape: (1, 554)
support_vectors_ shape: (554, 12)
intercept_: [-0.]
```

We have 554 support vectors, each 12-dimensional. The dual coefficients alternate perfectly between `-0.05` and `+0.05` (i.e., `sign = -, +, -, +, ...`), except for the last two entries which have magnitude `0.02049`.

### 2. Recognizing the structure

The alternating dual coefficients mean the support vectors are perfectly interleaved by class: `-1, +1, -1, +1, ...`. This is an artificial construction — real SVM training rarely produces this pattern.

Computing the weight vector:
```python
w = data.dual_coef_ @ data.support_vectors_
# w ≈ [-0.66, -0.05, 0.53, -0.43, 2.12, -0.82, 1.87, 0.31, -0.32, 0.40, 0.93, 0.68]
```

### 3. Computing slack variables

For each support vector, the decision function output is:
```python
fx = sv @ w + b
yfx = ys * fx          # yᵢ · f(xᵢ)
slack = max(0, 1 - yfx)
```

This reveals:

| SV indices | `α` | `ξ` | Meaning |
|-----------|-----|-----|---------|
| 0–551 | `C = 0.05` | `> 0` | Bounded SVs — within the margin ("oversteppers with slack") |
| 552–553 | `0.02049 < C` | `= 0` | Margin SVs — exactly on the decision boundary |

The slack values for the 552 bounded SVs fall into two distinct bands:
- **~0.44** (call it bit `0`)
- **~0.75** (call it bit `1`)

### 4. Decoding the flag

Grouping the 554 SVs into 277 consecutive pairs `(class=-1, class=+1)`, each pair provides 2 bits of information:

| Slack of class −1 SV | Slack of class +1 SV | Bits (neg, pos) |
|---------------------|---------------------|-----------------|
| ~0.44 (low) | ~0.44 (low) | `0, 0` |
| ~0.44 (low) | ~0.75 (high) | `0, 1` |
| ~0.75 (high) | ~0.44 (low) | `1, 0` |
| ~0.75 (high) | ~0.75 (high) | `1, 1` |

The last pair (indices 552–553) has zero slack and acts as a sentinel (excluded). Reading the 276 remaining pairs as alternating bits (neg, pos) and converting to ASCII yields:

```
SVSLACK\x00\x007grey{du4l_0pt1m1z4t10n_l3ft_th3_supp0rt_v3ct0rs_b3h1nd}
```

The flag portion is `grey{du4l_0pt1m1z4t10n_l3ft_th3_supp0rt_v3ct0rs_b3h1nd}`.

---

## Solution Script

```python
#!/usr/bin/env python3
import pickle
import numpy as np

with open("svc_dual_params.pkl", "rb") as f:
    model = pickle.load(f)

sv = model.support_vectors_
dc = model.dual_coef_[0]
ys = np.sign(dc)

w = (model.dual_coef_ @ sv)[0]
b = model.intercept_[0]
yfx = ys * (sv @ w + b)
slack = np.maximum(0, 1 - yfx)

slack_neg = slack[0::2][:-1]  # class -1, drop last pair (sentinel)
slack_pos = slack[1::2][:-1]  # class +1, drop last pair

bit_neg = (slack_neg > 0.5).astype(int)
bit_pos = (slack_pos > 0.6).astype(int)

bits = []
for i in range(len(bit_neg)):
    bits += [int(bit_neg[i]), int(bit_pos[i])]

flag = ""
for i in range(0, len(bits), 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i + j]
    flag += chr(byte)

flag = flag[flag.index("grey{"):flag.index("}") + 1]
print(flag)
```

---

## Verification

```bash
$ python3 verify.py grey{du4l_0pt1m1z4t10n_l3ft_th3_supp0rt_v3ct0rs_b3h1nd}
correct
```

---

## Key Insight

The challenge title **"Duality in All Things"** and the flavour text directly reference concepts from SVM theory:

- **Primal ↔ Dual** — the two equivalent formulations of the SVM objective
- **Regularization ↔ Oversteppers** — the `C` parameter controls how many support vectors "overstep" the margin (bounded SVs with `α = C`)
- **Oversteppers ↔ Slack** — every bounded support vector has a non-zero slack variable `ξᵢ`

The slack variables, which are normally just an optimization artifact, are repurposed here as a binary data channel. Each support vector pair's two slack values encode two bits of the flag. The margin SVs (last pair, `ξ = 0`) serve as a natural delimiter.

> "Where there is a challenge, is there a flag?" — Yes, hidden in the slack of the oversteppers.
