from dictionary import MNEMONIC_DICT_EN
from fcsr import FCSR


KNOWN_WORDS = ["happy", "meal", "family"]
TOTAL_WORDS = 12


def words_to_bits(words: list[str]) -> list[int]:
    bits: list[int] = []
    for word in words:
        idx = MNEMONIC_DICT_EN.index(word)
        bits.extend(int(bit) for bit in format(idx, "07b"))
    return bits


def find_shortest_fcsr(prefix_bits: list[int]) -> tuple[int, int, int]:
    n_bits = len(prefix_bits)

    for state_len in range(1, n_bits):
        initial_state = prefix_bits[:state_len]

        for mask in range(1 << (state_len - 1)):
            taps = [(mask >> i) & 1 for i in range(state_len - 1)] + [1]
            max_carry = sum(taps)

            for m0 in range(max_carry + 1):
                state = initial_state[:]
                carry = m0
                ok = True

                for expected_bit in prefix_bits:
                    comp = carry + sum(x & y for (x, y) in zip(taps, state[::-1]))
                    state.append(comp % 2)
                    carry = comp // 2

                    if state.pop(0) != expected_bit:
                        ok = False
                        break

                if not ok:
                    continue

                q_plus_1 = int("".join(map(str, taps[::-1])) + "0", 2)
                q = q_plus_1 - 1
                a = int("".join(map(str, initial_state[::-1])), 2)
                return q, m0, a

    raise RuntimeError("No valid FCSR found")


def main() -> None:
    prefix_bits = words_to_bits(KNOWN_WORDS)
    q, m, a = find_shortest_fcsr(prefix_bits)

    generator = FCSR(q, m, a)
    words = [MNEMONIC_DICT_EN[generator.get_idx(7)] for _ in range(TOTAL_WORDS)]

    print(f"Recovered parameters: q={q}, m={m}, a={a}")
    print("Mnemonic:", " ".join(words))
    print("Flag:", "VolgaCTF{" + "_".join(words) + "}")


if __name__ == "__main__":
    main()
