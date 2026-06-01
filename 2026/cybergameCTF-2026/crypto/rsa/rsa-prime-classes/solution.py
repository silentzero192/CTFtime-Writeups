#!/usr/bin/env python3
import ast
import math
import re
from pathlib import Path

import gmpy2


def parse_list(source: str, name: str) -> list[int]:
    pattern = rf"{name}\s*=\s*\[(.*?)\]\n\n"
    match = re.search(pattern, source, re.S)
    if not match:
        pattern = rf"{name}\s*=\s*\[(.*?)\]\nmain\(\)"
        match = re.search(pattern, source, re.S)
    if not match:
        raise ValueError(f"Could not parse {name} from main.py")
    return sorted(set(ast.literal_eval("[" + match.group(1) + "]")))


def parse_output(path: Path) -> tuple[int, int, int]:
    content = path.read_text()
    c_match = re.search(r"c:\s*(\d+)", content)
    n_match = re.search(r"n:\s*(\d+)", content)
    e_match = re.search(r"e:\s*(\d+)", content)
    if not (c_match and n_match and e_match):
        raise ValueError("Could not parse c, n, e from output.txt")
    return int(c_match.group(1)), int(n_match.group(1)), int(e_match.group(1))


def first_congruent_in_range(k_min: int, k_max: int, residue: int, modulus: int) -> int | None:
    if residue < k_min:
        residue += ((k_min - residue + modulus - 1) // modulus) * modulus
    if residue > k_max:
        return None
    return residue


def solve() -> str:
    main_source = Path("main.py").read_text()
    small_class = parse_list(main_source, "smallClass")
    middle_class = parse_list(main_source, "middleClass")
    big_class = parse_list(main_source, "bigClass")

    c, n, e = parse_output(Path("output.txt"))
    if e != 3:
        raise ValueError(f"Expected e=3, got e={e}")

    prefix = b"SK-CERT{"
    suffix = b"}"

    # We recover m from m^3 = c + k*n. The known prefix/suffix gives a k interval
    # for each candidate length. Congruence from divisibility by big+middle primes
    # collapses this to very few k values.
    for total_len in range(45, 70):
        unknown_len = total_len - len(prefix) - len(suffix)
        if unknown_len < 0:
            continue

        low = int.from_bytes(prefix + (b"\x00" * unknown_len) + suffix, "big")
        high = int.from_bytes(prefix + (b"\xff" * unknown_len) + suffix, "big")

        k_min = max(0, (low**3 - c + n - 1) // n)
        k_max = max(0, (high**3 - c) // n)
        if k_min > k_max:
            continue

        for middle_prime in middle_class:
            for big_prime in big_class:
                d = math.lcm(middle_prime, big_prime)
                modulus = d**3
                if math.gcd(n, modulus) != 1:
                    continue

                residue = (-c * pow(n, -1, modulus)) % modulus
                k = first_congruent_in_range(k_min, k_max, residue, modulus)
                while k is not None and k <= k_max:
                    root, exact = gmpy2.iroot(c + k * n, 3)
                    if exact:
                        m = int(root)
                        msg = m.to_bytes((m.bit_length() + 7) // 8, "big")
                        if (
                            len(msg) == total_len
                            and msg.startswith(prefix)
                            and msg.endswith(suffix)
                            and any(m % s == 0 for s in small_class)
                            and any(m % m2 == 0 for m2 in middle_class)
                            and any(m % b == 0 for b in big_class)
                        ):
                            return msg.decode()
                    k += modulus

    raise RuntimeError("Flag not found")


if __name__ == "__main__":
    print(solve())
