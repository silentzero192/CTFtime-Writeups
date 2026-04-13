MASK = (1 << 64) - 1


def rol(x, r):
    r &= 63
    if r == 0:
        return x & MASK
    return ((x << r) | (x >> (64 - r))) & MASK


def ror(x, r):
    r &= 63
    if r == 0:
        return x & MASK
    return ((x >> r) | (x << (64 - r))) & MASK


def generate_tables():
    rdx = 0x09E7448B1D3CF26A
    carry = 0
    step_rcx = 0x6C62272E07BB0142
    r10 = 0
    r9 = 0
    tables = []

    for pos in range(40):
        block = []
        rcx = 0
        rsi = 0
        rot = pos & 63

        for _ in range(256):
            fb = ((rdx >> 63) ^ (rdx & 1) ^ ((rdx >> 3) & 1) ^ ((rdx >> 2) & 1)) & MASK
            total = (rdx + fb + carry) & MASK
            carry = 1 if total < rdx else 0
            rdx = ror(total, 0x39)
            block.append((rol(rcx, rot) ^ (rsi ^ r10) ^ rdx) & MASK)
            rcx = (rcx + step_rcx) & MASK
            rsi = (rsi + r9) & MASK

        tables.append(block)
        r10 = (r10 + 0x9E3779B97F4A7C15) & MASK
        r9 = (r9 + 0xBF58476D1CE4E5B9) & MASK

    return tables


def target_bytes():
    qwords = (
        0xF0C553137025AFD6,
        0x376DDFC434D0F4D4,
        0x04F9BDE7A77AE197,
        0x0A89E4C1254BA31B,
        0xB7C0F25B3F70D12B,
    )
    return b"".join(q.to_bytes(8, "little") for q in qwords)


def recover_candidate(tables, ah):
    r9 = (ah & 0xFF) << 32
    rbp = 0x0000070E71C5389D
    r10 = 0x823EAF93561AD964
    r11 = 0x0000070E71C5389D
    mult = 0xD2A98B26625EEE7B
    out = []

    for i, target in enumerate(target_bytes()):
        idx = ((r11 >> 56) ^ (r9 & 0xFF)) & 0xFF
        derived = tables[i][idx] & 0xFF
        out.append(target ^ derived)

        rdx = (r10 + r11) & MASK
        rcx = r9 ^ rdx
        rcx = ror(rcx, 0x38)
        rbp = (rbp + rcx) & MASK
        rax = r10 ^ rbp
        rax = ror(rax, 0x2D)
        rdx = (rdx + rax) & MASK
        rcx ^= rdx
        rcx = ror(rcx, 0x18)
        r9 = rcx
        rbp = (rbp + rcx) & MASK
        rdx = (rdx + rbp) & MASK
        rdx = ror(rdx, 0x25)
        r11 = rdx
        rax ^= rbp
        r10 = ror(rax, 1)
        r10 = (r10 * mult) & MASK
        r10 ^= ((0xAAAAAAAAAAAAAAAB * i) & MASK) ^ rdx

    return bytes(out)


def main():
    tables = generate_tables()

    for ah in range(256):
        candidate = recover_candidate(tables, ah)
        if candidate.startswith(b"RS{"):
            print(candidate.rstrip(b"\x00").decode())
            print(candidate.hex())
            return

    raise RuntimeError("no flag-like candidate found")


if __name__ == "__main__":
    main()
