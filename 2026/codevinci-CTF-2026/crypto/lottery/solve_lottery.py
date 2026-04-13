#!/usr/bin/env python3
"""Exact cover solver for Lottery CTF using Algorithm X."""

import hashlib
import json
import itertools
import math
import sys
import time
from typing import List, Tuple, Set, Dict

V = 19
K = 3
T = 2
MAX_TICKETS = 58


def get_flag(tickets: List[List[int]]) -> str:
    normalized = sorted([tuple(sorted(t)) for t in tickets])
    payload = json.dumps(normalized).encode()
    digest = hashlib.sha256(payload).hexdigest()[:16]
    return f"CodeVinci{{not_real_flag_{digest}}}"


def build_matrix() -> Tuple[List[Tuple[int, ...]], List[Set[Tuple[int, ...]]], Dict[Tuple[int, ...], Set[int]]]:
    rng = range(V)
    triples = list(itertools.combinations(rng, K))
    triple_pairs = [set(itertools.combinations(triple, T)) for triple in triples]

    pair_to_rows = {pair: set() for pair in itertools.combinations(rng, T)}
    for row_idx, pairs in enumerate(triple_pairs):
        for pair in pairs:
            pair_to_rows[pair].add(row_idx)

    return triples, triple_pairs, pair_to_rows


def solve_exact_cover(triples: List[Tuple[int, ...]], triple_pairs: List[Set[Tuple[int, ...]]],
                      pair_to_rows: Dict[Tuple[int, ...], Set[int]]) -> List[Tuple[int, ...]]:
    columns = {pair: set(rows) for pair, rows in pair_to_rows.items()}
    row_map = triple_pairs
    solution_rows: List[int] = []
    start = time.time()
    time_limit = 60

    def cover_column(column):
        rows = columns.pop(column)
        removed = []
        for row in rows:
            for c in row_map[row]:
                if c == column:
                    continue
                columns[c].remove(row)
                removed.append((c, row))
        return column, rows, removed

    def uncover_column(data):
        column, rows, removed = data
        for c, row in reversed(removed):
            columns[c].add(row)
        columns[column] = rows

    def dfs() -> bool:
        if not columns:
            return True
        if len(solution_rows) >= MAX_TICKETS:
            return False
        if time.time() - start > time_limit:
            raise TimeoutError("Timeout exceeded")

        column = min(columns, key=lambda c: len(columns[c]))
        data = cover_column(column)
        rows_snapshot = list(data[1])

        for row in rows_snapshot:
            solution_rows.append(row)
            covered_columns = []
            for c in row_map[row]:
                if c == column:
                    continue
                covered_columns.append(cover_column(c))
            if dfs():
                return True
            for info in reversed(covered_columns):
                uncover_column(info)
            solution_rows.pop()
        uncover_column(data)
        return False

    if not dfs():
        raise SystemExit("Solution not found")
    return [triples[idx] for idx in solution_rows]


def main() -> None:
    triples, triple_pairs, pair_map = build_matrix()
    tickets = solve_exact_cover(triples, triple_pairs, pair_map)

    print(f"Found {len(tickets)} tickets (<= {MAX_TICKETS})")
    print(f"FLAG: {get_flag([list(t) for t in tickets])}")
    print(json.dumps([list(t) for t in tickets], indent=2))


if __name__ == "__main__":
    main()
