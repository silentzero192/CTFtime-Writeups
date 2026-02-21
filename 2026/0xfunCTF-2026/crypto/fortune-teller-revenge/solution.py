import bisect


def solve():
    M = 1 << 64
    A = 2862933555777941757
    C = 3037000493

    JUMP = 100000
    A_JUMP = pow(A, JUMP, M)
    C_JUMP = 8391006422427229792

    B = (A * A_JUMP) % M
    D = (A * C_JUMP + C) % M

    g1 = 1806652711
    g2 = 3521198783
    g3 = 509686811

    g1_high = g1 << 32
    g2_high = g2 << 32
    g3_high = g3 << 32

    R1 = (g2_high - (B * g1_high + D) % M) % M
    base = (-R1) % M

    half = 1 << 16
    U_list = []
    for a in range(half):
        U = (B * a + base) % M
        U_list.append((U, a))
    U_list.sort(key=lambda x: x[0])
    U_vals = [u for u, _ in U_list]

    for b in range(half):
        T = (B * b * half) % M
        L = (-T) % M
        R = (L + (1 << 32) - 1) % M
        intervals = []
        if L <= R:
            intervals.append((L, R))
        else:
            intervals.append((L, M - 1))
            intervals.append((0, R))
        for low, high in intervals:
            left = bisect.bisect_left(U_vals, low)
            right = bisect.bisect_right(U_vals, high)
            for idx in range(left, right):
                u, a = U_list[idx]
                x = a + b * half
                y = (B * x + base) % M
                if y >= (1 << 32):
                    continue
                R2 = (g3_high - (B * g2_high + D) % M) % M
                z = (B * y - R2) % M
                if z < (1 << 32):
                    s5 = g3_high + z
                    next_states = []
                    s = s5
                    for _ in range(5):
                        s = (A * s + C) % M
                        next_states.append(s)
                    return next_states
    raise ValueError("No solution found")


if __name__ == "__main__":
    result = solve()
    print(" ".join(str(v) for v in result))
