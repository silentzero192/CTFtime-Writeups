K.<x> = GF(2^8, modulus='random', impl='ntl')
F.<t> = PolynomialRing(GF(2))


def get_random_byte(field):
    seed = field.random_element()
    while True:
        yield seed.integer_representation()
        seed *= seed


def encrypt(plaintext):
    ciphertext = b''
    prng = get_random_byte(K)

    for i_byte in plaintext:
        ciphertext += (i_byte ^^ next(prng)).to_bytes(1, 'big')

    return ciphertext


if __name__ == '__main__':
    with open('flag.png', 'rb') as fd:
        flag_bytes = fd.read()

    ciphertext = encrypt(flag_bytes)

    with open('encrypted_flag', 'wb') as fd:
        fd.write(ciphertext)
