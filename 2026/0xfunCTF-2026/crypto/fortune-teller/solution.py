import bisect


def solve():
    M = 1 << 64
    A = 2862933555777941757
    C = 3037000493

    # given glimpses (high 32 bits of s1, s2, s3)

    h1 = 2576816260
    h2 = 2593472876
    h3 = 856520643

    h1_shift = h1 << 32
    h2_shift = h2 << 32
    h3_shift = h3 << 32

    R1 = (-A * h1_shift - C + h2_shift) % M
    R2 = (-A * h2_shift - C + h3_shift) % M

    half = 1 << 16
    # precompute for low 16 bits
    U_list = []
    for a in range(half):
        U = (A * a - R1) % M
        U_list.append((U, a))
    U_list.sort(key=lambda x: x[0])
    U_vals = [u for u, _ in U_list]

    # search over high 16 bits
    for b in range(half):
        T = (A * b * (1 << 16)) % M
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
                u_val, a = U_list[idx]
                x = a + b * half
                y = (A * x - R1) % M
                if y >= (1 << 32):
                    continue
                z = (A * y - R2) % M
                if z < (1 << 32):
                    # found the correct low bits
                    s1 = h1_shift + x
                    s2 = h2_shift + y
                    s3 = h3_shift + z
                    # compute next five full states
                    next_states = []
                    s = s3
                    for _ in range(5):
                        s = (A * s + C) % M
                        next_states.append(s)
                    return next_states

    raise ValueError("No solution found")


if __name__ == "__main__":
    result = solve()
    print(" ".join(str(v) for v in result))
