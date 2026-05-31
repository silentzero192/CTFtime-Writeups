# SABLE — greyCTF Quals 2026 (AI)

**Category:** `AI`  
**Flag:** `grey{w40w_Y0u_h4Z_a_L0t_oF_Fr3n5_inDeEd_:0}`

---

## Challenge Overview

```
My spam detector is very smart. It looks at a user's friends, decides which
friends matter most, and then confidently announces whether the user is suspicious.

I wonder just how many friends you have... ;)

nc challs.nusgreyhats.org 38267
```

We are given a server that runs a graph attention model to classify a target user as `suspicious` or `low-risk`. The server provides the model code (`model.py`), utility code (`graph_utils.py`), the pre-trained weights (`model.pt`), and the public graph data (`public_graph.json`). The goal is to craft a JSON payload that adds fake "friend" nodes to the graph, causing the model's risk score to drop below `0.05`, which reveals the flag.

### Files Provided

| File | Purpose |
|------|---------|
| `model.py` | PyTorch model definition (SDPAEgoSpamNet) |
| `model.pt` | Pre-trained model weights |
| `graph_utils.py` | Graph parsing, plausibility checks, payload validation |
| `public_graph.json` | Base social graph with 6 existing neighbors of the target |
| `server.py` | Challenge server logic |
| `requirements.txt` | Dependencies (torch, numpy) |

---

## Model Architecture

The model is a single-head graph attention network using PyTorch's `scaled_dot_product_attention`:

```
SDPAEgoSpamNet:
  q_proj: Linear(8 → 4)    # Query projection from target features
  k_proj: Linear(8 → 4)    # Key projection from neighbor features
  v_proj: Linear(8 → 4)    # Value projection from neighbor features
  target_proj: Linear(8 → 4)  # Target feature projection
  classifier: Linear(8 → 1)   # Final binary classifier
```

### Forward Pass

1. **Target feature vector** `x_target` (8-dim) is projected to query `q = W_q · x_target + b_q`
2. **Neighbor feature vectors** `x_neighbors` (N × 8) are projected to keys `k = W_k · x_neighbors` and values `v = W_v · x_neighbors`
3. **Scaled dot-product attention** computes attended values: `attended = softmax(q·k^T / √d) · v`
4. **Target projection**: `target_part = tanh(W_t · x_target + b_t)`
5. **Classification**: `logit = W_c · [target_part || attended] + b_c`
6. **Risk**: `σ(logit)`

### Critical Weight Analysis

When we inspect the model weights, we find they are **extremely sparse**:

```
q_proj.weight = [[0,0,0,0,0,0,0,0],        # All zeros!
                 [0,0,0,0,0,0,0,0],
                 [0,0,0,0,0,0,0,0],
                 [0,0,0,0,0,0,0,0]]
q_proj.bias   = [2, 0, 0, 0]                 # Only first element non-zero
```

This means **q = [2, 0, 0, 0] regardless of the target's features** — the query is a fixed constant!

```
k_proj.weight row 0: [0, 0, -1, -1, 0.35, 3.4, 3.4, 0.35]
k_proj.weight rows 1-3: all zeros
```

Therefore each neighbor's key is `k = [k₀, 0, 0, 0]` where:

```
k₀ = -report_rate - external_link_rate + 0.35·profile_realness
     + 3.4·shared_audience_overlap + 3.4·interaction_strength
     + 0.35·trust_score
```

The attention score for neighbor `i` is `q·kᵢᵀ / √4 = 2·k₀ / 2 = k₀`, so:

**Attention weight ∝ exp(k₀)**

Similarly, `v_proj` has only 2 non-zero rows:

```
v_proj row 0: [0, 0, 2.4, 2.7, -1.9, 1.7, 1.7, -1.9]
v_proj row 1: [0, 0, -0.6, -0.6, 1.0, -0.1, -0.1, 1.0]
```

So `v = [v₀, v₁, 0, 0]` where:

```
v₀ = 2.4·rr + 2.7·elr - 1.9·pr + 1.7·sao + 1.7·is_ - 1.9·ts
v₁ = -0.6·rr - 0.6·elr + 1.0·pr - 0.1·sao - 0.1·is_ + 1.0·ts
```

(rr=report_rate, elr=external_link_rate, pr=profile_realness, sao=shared_audience_overlap, is_=interaction_strength, ts=trust_score)

The classifier is also sparse:

```
classifier.weight = [0, 0, 0, 0, 8.0, -1.44, 0, 0]
classifier.bias   = -2.37

target_proj.weight = all zeros
target_proj.bias   = [0.05, 0, 0, 0]
```

Since `target_part = tanh([0.05, 0, 0, 0]) ≈ [0.05, 0, 0, 0]` and `classifier.weight[:4] = 0`, the target projection contributes nothing.

**The final logit simplifies to:**

```
logit = 8·a₀ - 1.44·a₁ - 2.37
```

where `a₀` and `a₁` are the attention-weighted averages of `v₀` and `v₁` across all neighbors.

---

## Existing Graph Analysis

The base graph has the target connected to 6 neighbors. Their key statistics:

| Neighbor | Role | k₀ | exp(k₀) | v₀ | v₁ |
|----------|------|----|---------|-----|-----|
| user_giveaway_ring_01 | spam | 5.02 | 151.6 | 7.86 | -1.22 |
| user_giveaway_ring_02 | spam | 4.80 | 121.8 | 7.18 | -1.04 |
| user_linkfarm_17 | spam | 4.66 | 105.7 | 5.99 | -0.74 |
| user_creator_21 | normal | 1.85 | 6.3 | -2.56 | 1.70 |
| user_lurker_44 | normal | 0.84 | 2.3 | -2.56 | 1.43 |
| user_mod_09 | normal | 1.42 | 4.2 | -3.18 | 1.88 |

The spam neighbors dominate attention (exp values 105–152 vs 2–6 for normal neighbors) and have large positive v₀ values, driving the logit to **53.4** and risk to **1.0**.

---

## Attack Strategy

We can submit up to **6 new friend nodes**, each connected to the target, with custom feature vectors. Our goal: make `risk = σ(logit) < 0.05` i.e. `logit < -2.944`.

### Key Tension

To **steal attention** from spam neighbors, we need high `k₀`, which requires high `shared_audience_overlap` and `interaction_strength`:

```
k₀ = -rr - elr + 0.35·pr + 3.4·sao + 3.4·is_ + 0.35·ts
```

But high `sao` and `is_` also increase `v₀` (coefficient +1.7 each), making the logit more positive. Meanwhile low `v₀` requires **low** `sao` and `is_`:

```
v₀ = 2.4·rr + 2.7·elr - 1.9·pr + 1.7·sao + 1.7·is_ - 1.9·ts
```

The sweet spot balances attention-stealing power with negative enough `v₀`.

### Plausibility Constraints

The server enforces several "plausibility" rules to prevent obviously fake profiles:

1. `rr ≥ max(0, sao - 0.70) · 0.36` (high overlap requires more reports)
2. `elr ≥ max(0, is_ - 0.70) · 0.36` (high interaction requires more external links)
3. `rr + elr ≥ max(0, sao + is_ - 1.30) · 0.24` (combined floor)
4. `sao - is_ ≤ 0.24` (can't be too imbalanced)
5. Not `(rr+elr < 0.09 AND pr+ts > 1.84 AND sao+is_ > 1.50)` (no "implausibly perfect" profiles)

### Diversity Constraints

All 6 submitted nodes must be different:
- **Full feature L1 distance** ≥ 0.055 between any pair (all 8 features)
- **Active feature L1 distance** ≥ 0.020 between any pair (features [2..7] that affect the model)

---

## Optimization

We derived the formula for the logit after adding N new neighbors:

```
logit = (old_num + N·exp(k₀)·(8v₀ - 1.44v₁)) / (old_den + N·exp(k₀)) - 2.37
```

where:
- `old_num = 21839.5` (weighted sum of existing contributions)
- `old_den = 391.85` (sum of existing exp values)

A grid search over `(sao, is_)` pairs (0–1, step 0.02) with `rr, elr` at their plausibility minima revealed the optimal region:

| sao | is_ | rr | elr | k₀ | exp(k₀) | v₀ | v₁ | logit | risk |
|-----|-----|----|-----|----|---------|----|----|-------|------|
| 0.94 | 0.74 | 0.087 | 0.016 | 6.25 | 518 | -0.75 | 1.78 | -3.69 | 0.024 |
| 0.92 | 0.74 | 0.080 | 0.016 | 6.25 | 518 | -0.74 | 1.78 | -3.68 | 0.025 |
| 0.96 | 0.72 | 0.095 | 0.009 | 6.31 | 550 | -0.69 | 1.77 | -3.70 | 0.024 |

All three configurations produce risk well below 0.05.

---

## Final Payload

We created 6 nodes with slightly varied features around the optimum to satisfy diversity:

```json
{
  "new_nodes": [
    {
      "id": "friend_0000",
      "features": {
        "post_rate_norm": 0.0,
        "profile_age_norm": 0.06,
        "report_rate": 0.087,
        "external_link_rate": 0.016,
        "profile_realness": 1.0,
        "shared_audience_overlap": 0.94,
        "interaction_strength": 0.74,
        "trust_score": 1.0
      }
    },
    {
      "id": "friend_0001",
      "features": {
        "post_rate_norm": 0.02,
        "profile_age_norm": 0.08,
        "report_rate": 0.091,
        "external_link_rate": 0.012,
        "profile_realness": 1.0,
        "shared_audience_overlap": 0.95,
        "interaction_strength": 0.73,
        "trust_score": 1.0
      }
    },
    {
      "id": "friend_0002",
      "features": {
        "post_rate_norm": 0.04,
        "profile_age_norm": 0.1,
        "report_rate": 0.084,
        "external_link_rate": 0.019,
        "profile_realness": 1.0,
        "shared_audience_overlap": 0.93,
        "interaction_strength": 0.75,
        "trust_score": 1.0
      }
    },
    {
      "id": "friend_0003",
      "features": {
        "post_rate_norm": 0.06,
        "profile_age_norm": 0.0,
        "report_rate": 0.095,
        "external_link_rate": 0.009,
        "profile_realness": 1.0,
        "shared_audience_overlap": 0.96,
        "interaction_strength": 0.72,
        "trust_score": 1.0
      }
    },
    {
      "id": "friend_0004",
      "features": {
        "post_rate_norm": 0.08,
        "profile_age_norm": 0.02,
        "report_rate": 0.08,
        "external_link_rate": 0.016,
        "profile_realness": 1.0,
        "shared_audience_overlap": 0.92,
        "interaction_strength": 0.74,
        "trust_score": 1.0
      }
    },
    {
      "id": "friend_0005",
      "features": {
        "post_rate_norm": 0.1,
        "profile_age_norm": 0.04,
        "report_rate": 0.087,
        "external_link_rate": 0.023,
        "profile_realness": 1.0,
        "shared_audience_overlap": 0.94,
        "interaction_strength": 0.76,
        "trust_score": 1.0
      }
    }
  ],
  "new_edges": [
    ["user_target", "friend_0000"],
    ["user_target", "friend_0001"],
    ["user_target", "friend_0002"],
    ["user_target", "friend_0003"],
    ["user_target", "friend_0004"],
    ["user_target", "friend_0005"]
  ]
}
```

### Why It Works

The crafted nodes have:
- **Moderately high** `shared_audience_overlap` (0.92–0.96) and `interaction_strength` (0.72–0.76) to steal attention from spam neighbors
- **Low** `report_rate` (0.08–0.095) and `external_link_rate` (0.009–0.023), kept just above the plausibility floor, to keep v₀ negative
- **Maximum** `profile_realness` (1.0) and `trust_score` (1.0) to maximize v₁ (pushing logit further negative)
- Feature variations for all 6 nodes satisfy both full (≥0.055) and active (≥0.020) pairwise diversity

Together they capture **~89% of the attention**, and their collective v₀/v₁ values drive the logit to **-3.67**, giving a risk of **0.025** — well below the 0.05 threshold.

---

## Submission

```bash
$ cat payload.json | nc challs.nusgreyhats.org 38267
```

**Response:**
```json
{
  "flag": "grey{w40w_Y0u_h4Z_a_L0t_oF_Fr3n5_inDeEd_:0}",
  "message": "target accepted as low-risk",
  "ok": true,
  "risk": 0.024887,
  "threshold": 0.05
}
```

## Key Takeaways

1. **Never trust sparse weight patterns** — the model's dramatic sparsity revealed exactly which features mattered and how to manipulate them
2. **White-box ML attacks** — full model access enables precise adversarial example crafting
3. **Attention hijacking** — if you can create inputs that dominate the softmax, you control the model's output
4. **Constraints as guidance** — the plausibility checks actually help by narrowing the search space
