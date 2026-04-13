#!/usr/bin/env python3
import argparse
import ast
import math
import string
import sys
from collections import Counter, defaultdict
from functools import reduce
from pathlib import Path


FLAG_PREFIX = "RS{"
INNER_CHARSETS = [
    set((string.ascii_letters + string.digits + "_").encode()),
    set((string.ascii_letters + string.digits + "_-!").encode()),
]


def load_challenge(path):
    text = Path(path).read_text()
    log = ast.literal_eval(text.split("Log: ", 1)[1].split("\nCiphertext:", 1)[0])
    ct = bytes.fromhex(text.split("Ciphertext: ", 1)[1].strip())
    return log, ct


def recover_modulus(log):
    candidates = []
    for i in range(len(log) - 5):
        x0, x1, x2, x3, x4, x5 = log[i : i + 6]
        e1 = (x2 - x1) * (x4 - x3) - (x3 - x2) * (x3 - x2)
        e2 = (x3 - x2) * (x5 - x4) - (x4 - x3) * (x4 - x3)
        g = math.gcd(abs(e1), abs(e2))
        if g.bit_length() > 128:
            candidates.append(g)

    if not candidates:
        raise ValueError("failed to recover modulus")

    return reduce(math.gcd, candidates)


def recover_heads(log, modulus):
    counts = Counter()
    for i in range(len(log) - 2):
        x, y, z = log[i : i + 3]
        den = (y - x) % modulus
        if den == 0:
            continue
        a = ((z - y) % modulus) * pow(den, -1, modulus) % modulus
        b = (y - a * x) % modulus
        counts[(a, b)] += 1

    heads = [pair for pair, count in counts.most_common() if count > 1]
    if not heads:
        raise ValueError("failed to recover heads")
    return heads


def label_states(log, modulus, heads):
    states = []
    for i in range(len(log) - 1):
        x, y = log[i], log[i + 1]
        matches = [idx for idx, (a, b) in enumerate(heads) if (a * x + b) % modulus == y]
        if len(matches) != 1:
            raise ValueError(f"expected unique head for transition {i}, got {matches}")
        states.append(matches[0])
    return states


def transition_log_probs(states, num_states):
    trans = defaultdict(Counter)
    for a, b in zip(states, states[1:]):
        trans[a][b] += 1

    logp = [[0.0] * num_states for _ in range(num_states)]
    for src in range(num_states):
        total = sum(trans[src].values()) + num_states
        for dst in range(num_states):
            logp[src][dst] = math.log((trans[src][dst] + 1) / total)
    return logp


def beam_search(ciphertext, last_value, last_state, heads, modulus, logp, allowed_inner, beam_limit):
    beam = [(0.0, last_value, last_state, "")]

    for i, c in enumerate(ciphertext):
        new_beam = []
        for score, value, prev_state, plaintext in beam:
            for next_state, (a, b) in enumerate(heads):
                next_value = (a * value + b) % modulus
                plain = (next_value & 0xFF) ^ c

                if i < len(FLAG_PREFIX):
                    if plain != ord(FLAG_PREFIX[i]):
                        continue
                elif i == len(ciphertext) - 1:
                    if plain != ord("}"):
                        continue
                elif plain not in allowed_inner:
                    continue

                new_beam.append(
                    (
                        score + logp[prev_state][next_state],
                        next_value,
                        next_state,
                        plaintext + chr(plain),
                    )
                )

        if not new_beam:
            return []

        new_beam.sort(key=lambda item: item[0], reverse=True)
        beam = new_beam[:beam_limit]

    return beam


def recover_flag(log, ciphertext, beam_limit=50000):
    modulus = recover_modulus(log)
    heads = recover_heads(log, modulus)
    states = label_states(log, modulus, heads)
    logp = transition_log_probs(states, len(heads))

    for allowed in INNER_CHARSETS:
        beam = beam_search(
            ciphertext,
            log[-1],
            states[-1],
            heads,
            modulus,
            logp,
            allowed,
            beam_limit,
        )
        if beam:
            return modulus, heads, states, beam[0][3]

    raise ValueError("failed to recover flag")


def main():
    parser = argparse.ArgumentParser(
        description="Recover the flag for the Mark Compass challenge."
    )
    parser.add_argument(
        "--logbook",
        default="logbook.txt",
        help="path to the challenge logbook",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print recovered parameters before the flag",
    )
    args = parser.parse_args()

    log, ciphertext = load_challenge(args.logbook)
    modulus, heads, states, flag = recover_flag(log, ciphertext)

    if args.verbose:
        print(f"Recovered modulus bit length: {modulus.bit_length()}")
        print(f"Recovered heads: {len(heads)}")
        print(f"Recovered labeled transitions: {len(states)}")

    print(flag)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        sys.exit(1)
