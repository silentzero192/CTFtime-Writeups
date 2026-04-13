#!/usr/bin/env python3
import re
from math import gcd
from pathlib import Path


FLAG_RE = re.compile(r"RS\{[^}]+\}")


def parse_params(path: Path):
    lines = path.read_text().splitlines()
    chars = lines[1].strip()
    values = {}
    for line in lines[3:]:
        key, value = line.split("=")
        values[key.strip()] = int(value.strip())
    return chars, values


def generate_stream(chars, mods, seeds, multipliers):
    s1, s2, s3 = seeds
    a1, a2, a3 = multipliers
    seen = set()
    out = []

    while True:
        s1 = (a1 * s1) % mods[0]
        s2 = (a2 * s2) % mods[1]
        s3 = (a3 * s3) % mods[2]

        state = (s1, s2, s3)
        if state in seen:
            break
        seen.add(state)

        idx = (s1 - s2 + s3) % (mods[0] - 1)
        out.append(chars[idx])

    return "".join(out)


def recover_flag(chars, values):
    mods = (values["m1"], values["m2"], values["m3"])
    seeds = (values["s1"], values["s2"], values["s3"])

    hits = []
    for a1 in range(mods[0]):
        if gcd(a1, mods[0]) != 1:
            continue
        for a2 in range(mods[1]):
            if gcd(a2, mods[1]) != 1:
                continue
            for a3 in range(mods[2]):
                if gcd(a3, mods[2]) != 1:
                    continue

                stream = generate_stream(chars, mods, seeds, (a1, a2, a3))
                match = FLAG_RE.search(stream)
                if not match:
                    continue

                hits.append(
                    {
                        "multipliers": (a1, a2, a3),
                        "stream": stream,
                        "flag": match.group(0),
                        "offset": match.start(),
                    }
                )

    # The intended hit starts with the flag immediately.
    anchored_hits = [hit for hit in hits if hit["offset"] == 0]
    if len(anchored_hits) != 1:
        raise RuntimeError(f"Unexpected candidate set: {anchored_hits or hits}")

    return anchored_hits[0]


def main():
    chars, values = parse_params(Path("params.txt"))
    hit = recover_flag(chars, values)

    print(f"multipliers = {hit['multipliers']}")
    print(f"stream      = {hit['stream']}")
    print(f"flag        = {hit['flag']}")


if __name__ == "__main__":
    main()
