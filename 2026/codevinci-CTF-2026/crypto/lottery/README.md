# Lottery - Writeup

**Challenge Name:** `Lottery`
**Platform:** `CodeVinci CTF 2026`
**Category:** `Crypto`

## Goal (What was the task?)
Understand the Python lottery verifier, cover every 2-number combination across 19 symbols with ≤58 tickets of 3 numbers each, and submit the ticket set to get the CodeVinci flag (format `CodeVinci{...}`).

## Key Clues (What mattered?)

- `lottery.py` defines V=19 symbols, K=3 numbers per ticket, T=2 for pair coverage, and a `MAX_TICKETS=58` limit.
- `get_flag` hashes the normalized ticket set and prints `CodeVinci{not_real_flag_...}` (local flag) when coverage passes.
- Server (`lottery.codevinci.it:9975`) mirrors the same verifier and expects JSON list input via stdin.

## Plan (Your first logical approach)

- Enumerate all 3-combinations (tickets) from 19 symbols and map each ticket to the pairs it covers.
- Model coverage as an exact-cover problem: choose up to 58 tickets so every 2-combination appears at least once.
- Implement Algorithm X (Knuth) to search for a ticket set that covers all pairs and hash it to match the flag format.

## Steps (Clean execution)

1. Read `lottery.py` to extract the constants (V, K, T, max tickets) and understand the verification/flag logic.
2. Wrote `solve_lottery.py` to build the exact-cover matrix (rows=tickets, columns=pairs) and execute Algorithm X to cover all columns without exceeding 58 rows.
3. Ran `./solve_lottery.py`; it found 57 tickets, printed the normalized set, and derived the local flag `CodeVinci{not_real_flag_2da1463b3a30df64}`.
4. Connected to `lottery.codevinci.it:9975` with Python sockets, sent the same JSON ticket list, and received the remote flag.

## Solution Summary (What worked and why?)
The verifier is merely checking for combinatorial coverage of every 2-number pair among 19 symbols using tickets of size 3. Casting it as an exact-cover problem and applying Algorithm X allowed us to deterministically construct a ticket set of 57 triples within the 58-ticket cap. The normalized ticket list produced the local hash-based flag, and submitting the same list to the remote challenge revealed the official flag.

## Flag
CodeVinci{https://arxiv.org/abs/2307.12430_player_2da1463b3a30df64}

## Lessons Learned (make it reusable)

- A coverage/steiner system problem can often be reframed as exact cover by treating k-subsets as rows and t-subsets as columns.
- When brute force fails, Knuth's Algorithm X with column heuristics is a reliable way to find combinatorial designs under strict size limits.
- Automating submissions with scripts (instead of manual `nc`) avoids issues with blocked stdin/stdout and ensures reproducibility.

## Personal Cheat Sheet

- `itertools.combinations(range(V), K)` → generate candidate tickets.
- Algorithm X: choose column with fewest rows, recursively cover/uncover — great for combinatorial covering/packing.
- `json.dumps(tickets)` + socket send → submit ticket list to remote verifier.
