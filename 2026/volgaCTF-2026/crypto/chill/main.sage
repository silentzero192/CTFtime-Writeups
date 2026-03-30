FLAG = b'VolgaCTF{...}'
BIT_LENGTH = len(FLAG) * 8
K = IntegerModRing(2 ^ 22)


def gen_dsa_params():
    q = random_prime(2^BIT_LENGTH - 1, False, 2^(BIT_LENGTH-1))
    print('Q:', q)

    i = 2

    while not is_prime(i * q + 1):
        i += 1

    p = i * q + 1
    print('P:', p)

    mod_p = IntegerModRing(p)
    g = mod_p(2 ^ ((p - 1) / q))
    print('G:', g)

    return g, p, q


def gen_dsa_keys(g, p_ring, x):
    y = p_ring(g ^ x)
    print('Y:', y)

    return x, y


def dsa_sign(m, g, p_ring, q_ring, x, nonce_gen):
    r = s = 0
    cnt = 1

    while r == 0 or s == 0:
        print(f'Try #{cnt}')
        k = next(nonce_gen)
        r = q_ring(p_ring(g ^ k))
        s = q_ring(k ^ (-1) * (m + x * r))

        cnt += 1

    return r, s


def get_nonce(q_ring):
    seed = q_ring.random_element()

    while True:
        yield seed
        seed += q_ring(K.random_element())


if __name__ ==  '__main__':
    G, P, Q = gen_dsa_params()

    mod_p = IntegerModRing(P)
    mod_q = IntegerModRing(Q)

    X, Y = int.from_bytes(FLAG, 'big'), gen_dsa_keys(G, mod_p, int.from_bytes(FLAG, 'big'))

    nonce_gen = get_nonce(mod_q)

    m1 = b'message1'
    m2 = b'message2'

    print('Message #1')
    r1, s1 = dsa_sign(int.from_bytes(m1, 'big'), G, mod_p, mod_q, X, nonce_gen)
    print(f'(R1, S1): ({r1}, {s1})')

    print('Message #2')
    r2, s2 = dsa_sign(int.from_bytes(m2, 'big'), G, mod_p, mod_q, X, nonce_gen)
    print(f'(R2, S2): ({r2}, {s2})')
