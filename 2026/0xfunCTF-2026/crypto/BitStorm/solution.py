#!/usr/bin/env python3
import sys

MASK64 = 0xFFFFFFFFFFFFFFFF
taps = [0, 1, 3, 7, 13, 22, 28, 31]
SIZE = 32
STEPS = 60
TOTAL_EQ = STEPS * 64
TOTAL_BITS = SIZE * 64


def simulate(state0):
    """Return list of 60 outputs for given initial state (list of 32 ints)."""
    state = state0[:]
    outputs = []
    for _ in range(STEPS):
        s = state
        # ---- compute new_val ----
        new_val = 0
        for i in taps:
            val = s[i]
            mixed = val ^ ((val << 11) & MASK64) ^ (val >> 7)
            rot = (i * 3) % 64
            mixed = ((mixed << rot) | (mixed >> (64 - rot))) & MASK64
            new_val ^= mixed
        new_val ^= (s[-1] >> 13) ^ ((s[-1] << 5) & MASK64)
        new_val &= MASK64
        # ---- update state ----
        state = s[1:] + [new_val]
        # ---- compute output ----
        out = 0
        for i in range(SIZE):
            if i % 2 == 0:
                out ^= state[i]
            else:
                val = state[i]
                out ^= ((val >> 2) | (val << 62)) & MASK64
        outputs.append(out)
    return outputs


def main():
    # ----- given outputs from output.txt -----
    actual = [
        11329270341625800450,
        14683377949987450496,
        11656037499566818711,
        14613944493490807838,
        370532313626579329,
        5006729399082841610,
        8072429272270319226,
        3035866339305997883,
        8753420467487863273,
        15606411394407853524,
        5092825474622599933,
        6483262783952989294,
        15380511644426948242,
        13769333495965053018,
        5620127072433438895,
        6809804883045878003,
        1965081297255415258,
        2519823891124920624,
        8990634037671460127,
        3616252826436676639,
        1455424466699459058,
        2836976688807481485,
        11291016575083277338,
        1603466311071935653,
        14629944881049387748,
        3844587940332157570,
        584252637567556589,
        10739738025866331065,
        11650614949586184265,
        1828791347803497022,
        9101164617572571488,
        16034652114565169975,
        13629596693592688618,
        17837636002790364294,
        10619900844581377650,
        15079130325914713229,
        5515526762186744782,
        1211604266555550739,
        11543408140362566331,
        18425294270126030355,
        2629175584127737886,
        6074824578506719227,
        6900475985494339491,
        3263181255912585281,
        12421969688110544830,
        10785482337735433711,
        10286647144557317983,
        15284226677373655118,
        9365502412429803694,
        4248763523766770934,
        13642948918986007294,
        3512868807899248227,
        14810275182048896102,
        1674341743043240380,
        28462467602860499,
        1060872896572731679,
        13208674648176077254,
        14702937631401007104,
        5386638277617718038,
        8935128661284199759,
    ]

    # ----- build RHS vector (3840 bits) -----
    rhs = [0] * TOTAL_EQ
    for step, val in enumerate(actual):
        for bit in range(64):
            if (val >> bit) & 1:
                rhs[step * 64 + bit] = 1

    # ----- matrix A: 3840 rows, each a 2048-bit mask -----
    masks = [0] * TOTAL_EQ

    print(f"[*] Simulating {TOTAL_BITS} basis vectors...")
    for i in range(TOTAL_BITS):
        if i % 100 == 0:
            print(f"    progress: {i}/{TOTAL_BITS}")
        word = i // 64
        bit = i % 64
        state0 = [0] * SIZE
        state0[word] = 1 << bit
        outs = simulate(state0)
        for step, out_val in enumerate(outs):
            v = out_val
            while v:
                lsb = v & -v
                b = lsb.bit_length() - 1
                eq = step * 64 + b
                masks[eq] |= 1 << i
                v ^= lsb

    print("[*] Simulation done. Building equations...")

    # ----- prepare rows for elimination -----
    rows = [(masks[i], rhs[i]) for i in range(TOTAL_EQ) if masks[i] != 0 or rhs[i] != 0]
    print(f"    {len(rows)} non‑zero equations")

    # ----- Gaussian elimination over GF(2) (high columns first) -----
    pivots = []
    for col in reversed(range(TOTAL_BITS)):
        # find pivot row
        found = None
        for idx, (m, _) in enumerate(rows):
            if (m >> col) & 1:
                found = idx
                break
        if found is not None:
            pm, pr = rows.pop(found)
            pivots.append((col, pm, pr))
            # eliminate from other rows
            for j in range(len(rows)):
                if (rows[j][0] >> col) & 1:
                    rows[j] = (rows[j][0] ^ pm, rows[j][1] ^ pr)

    # check consistency
    for m, r in rows:
        if m != 0 or r != 0:
            print("[!] Inconsistent system!")
            sys.exit(1)

    # ----- back substitution (low columns first) -----
    pivots.sort(key=lambda x: x[0])  # ascending column
    x = [0] * TOTAL_BITS
    for col, mask, r in pivots:
        val = r
        lower = mask & ((1 << col) - 1)
        while lower:
            lsb = lower & -lower
            b = lsb.bit_length() - 1
            val ^= x[b]
            lower ^= lsb
        x[col] = val

    # ----- reconstruct initial state -----
    state = [0] * SIZE
    for i, bit_val in enumerate(x):
        if bit_val:
            word = i // 64
            bit = i % 64
            state[word] |= 1 << bit

    # ----- build seed_int (big‑endian 256 bytes) -----
    seed_int = 0
    for w in state:
        seed_int = (seed_int << 64) | w
    seed_bytes = seed_int.to_bytes(256, "big")
    flag_content = seed_bytes.rstrip(b"\x00")
    flag = b"0xfun{" + flag_content + b"}"
    print(f"\n[+] Flag recovered: {flag.decode()}")


if __name__ == "__main__":
    main()
