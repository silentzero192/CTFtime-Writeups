# -*- coding: utf-8 -*-
#!/usr/bin/env python3
import argparse
import os
import secrets
import struct

import numpy as np

# ============================================================
# Domain parameters
# ============================================================
Q = 3329
N = 80
K = 2
ETA1 = 2
ETA2 = 2


# ============================================================
# NTT setup
# ============================================================

def _find_primitive_root(q):
    order = q - 1
    factors = set()
    tmp = order
    d = 2
    while d * d <= tmp:
        while tmp % d == 0:
            factors.add(d)
            tmp //= d
        d += 1
    if tmp > 1:
        factors.add(tmp)
    for g in range(2, q):
        if all(pow(g, order // p, q) != 1 for p in factors):
            return g
    raise ValueError("no primitive root")


def _bit_rev(x, bits):
    r = 0
    for _ in range(bits):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


def _is_power_of_two(x: int) -> bool:
    return x > 0 and (x & (x - 1)) == 0


def _ntt_supported(q: int, n: int) -> bool:
    # This radix-2 NTT requires n to be a power of two and 2n | (q-1).
    return _is_power_of_two(n) and ((q - 1) % (2 * n) == 0)


def _setup_ntt(q, n):
    g = _find_primitive_root(q)
    psi = pow(g, (q - 1) // (2 * n), q)  # primitive 2n-th root of unity
    log_n = n.bit_length() - 1
    zetas = [pow(psi, _bit_rev(i, log_n), q) for i in range(n)]
    zetas_inv = [pow(z, q - 2, q) for z in zetas]
    n_inv = pow(n, -1, q)
    return zetas, zetas_inv, n_inv


if _ntt_supported(Q, N):
    ZETAS, ZETAS_INV, N_INV = _setup_ntt(Q, N)
else:
    ZETAS, ZETAS_INV, N_INV = None, None, None


# ============================================================
# Polynomial arithmetic in R_q = Z_q[X] / (X^N + 1)
# ============================================================

def poly_add(a, b):
    return (a + b) % Q


def poly_sub(a, b):
    return (a - b) % Q


def ntt(f):
    """Forward NTT (Cooley-Tukey butterfly)."""
    if ZETAS is None:
        raise ValueError("NTT is unsupported for current parameters (requires power-of-two N and 2N | Q-1)")
    a = np.array(f, dtype=np.int64).copy()
    k = 1
    length = N // 2
    while length >= 1:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * int(a[j + length])) % Q
                a[j + length] = (int(a[j]) - t) % Q
                a[j] = (int(a[j]) + t) % Q
        length //= 2
    return a


def ntt_inv(f):
    """Inverse NTT (Gentleman-Sande butterfly)."""
    if ZETAS_INV is None or N_INV is None:
        raise ValueError("NTT is unsupported for current parameters (requires power-of-two N and 2N | Q-1)")
    a = np.array(f, dtype=np.int64).copy()
    log_n = N.bit_length() - 1
    length = 1
    for d in range(log_n - 1, -1, -1):
        k = 1 << d
        for start in range(0, N, 2 * length):
            zeta = ZETAS_INV[k]
            k += 1
            for j in range(start, start + length):
                t = int(a[j])
                a[j] = (t + int(a[j + length])) % Q
                a[j + length] = (zeta * ((t - int(a[j + length])) % Q)) % Q
        length *= 2
    for j in range(N):
        a[j] = (int(a[j]) * N_INV) % Q
    return a


def poly_mul(a, b):
    """Multiply two polynomials in R_q via NTT."""
    if not _ntt_supported(Q, N):
        # Fallback for non-radix2-friendly parameters: negacyclic convolution
        # modulo X^N + 1 in Z_q[X].
        aa = np.array(a, dtype=np.int64) % Q
        bb = np.array(b, dtype=np.int64) % Q
        out = np.zeros(N, dtype=np.int64)
        for i in range(N):
            ai = int(aa[i])
            if ai == 0:
                continue
            for j in range(N):
                idx = i + j
                prod = ai * int(bb[j])
                if idx >= N:
                    out[idx - N] -= prod
                else:
                    out[idx] += prod
        return out % Q
    a_hat = ntt(a)
    b_hat = ntt(b)
    c_hat = (a_hat * b_hat) % Q
    return ntt_inv(c_hat)


def mat_vec_mul(M, v):
    """Matrix-vector product in R_q^{K}. M: (K,K,N), v: (K,N) -> (K,N)."""
    if not _ntt_supported(Q, N):
        result = np.zeros((K, N), dtype=np.int64)
        for i in range(K):
            acc = np.zeros(N, dtype=np.int64)
            for j in range(K):
                acc = (acc + poly_mul(M[i, j], v[j])) % Q
            result[i] = acc
        return result
    v_ntt = np.array([ntt(v[j]) for j in range(K)])
    result = np.zeros((K, N), dtype=np.int64)
    for i in range(K):
        acc = np.zeros(N, dtype=np.int64)
        for j in range(K):
            m_ntt = ntt(M[i, j])
            acc = (acc + m_ntt * v_ntt[j]) % Q
        result[i] = ntt_inv(acc)
    return result


def vec_inner(a, b):
    """Inner product of two vectors of polynomials. (K,N),(K,N) -> (N,)."""
    if not _ntt_supported(Q, N):
        acc = np.zeros(N, dtype=np.int64)
        for j in range(K):
            acc = (acc + poly_mul(a[j], b[j])) % Q
        return acc
    b_ntt = np.array([ntt(b[j]) for j in range(K)])
    acc = np.zeros(N, dtype=np.int64)
    for j in range(K):
        a_ntt = ntt(a[j])
        acc = (acc + a_ntt * b_ntt[j]) % Q
    return ntt_inv(acc)


# ============================================================
# Sampling
# ============================================================

def _rand_bits(count):
    byte_count = (count + 7) // 8
    raw = secrets.token_bytes(byte_count)
    bits = []
    for b in raw:
        for bit_pos in range(8):
            bits.append((b >> bit_pos) & 1)
            if len(bits) == count:
                return bits
    return bits


def cbd(eta):
    """Sample a polynomial with centred binomial distribution CBD_eta."""
    coeffs = np.zeros(N, dtype=np.int64)
    bits = _rand_bits(2 * eta * N)
    idx = 0
    for i in range(N):
        a = sum(bits[idx + j] for j in range(eta))
        b = sum(bits[idx + eta + j] for j in range(eta))
        coeffs[i] = (a - b) % Q
        idx += 2 * eta
    return coeffs


def uniform_poly():
    """Sample a uniformly random polynomial with coefficients in [0, Q)."""
    coeffs = np.zeros(N, dtype=np.int64)
    for i in range(N):
        while True:
            raw = int.from_bytes(secrets.token_bytes(2), "little")
            val = raw & 0x0FFF
            if val < Q:
                coeffs[i] = val
                break
    return coeffs


# ============================================================
# Message encoding
# ============================================================

# One message polynomial holds N bits = N/8 bytes; PKCS#7 block size must divide that
# so padded plaintext length is an exact number of blocks (no implicit zero bits after PKCS#7).
_PKCS7_BLOCK_SIZE = N // 8


def _pkcs7_pad(data: bytes, block_size: int = _PKCS7_BLOCK_SIZE) -> bytes:
    if not (1 <= block_size <= 255):
        raise ValueError("invalid PKCS#7 block size")
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes, block_size: int = _PKCS7_BLOCK_SIZE) -> bytes:
    if len(data) == 0 or (len(data) % block_size) != 0:
        raise ValueError("invalid PKCS#7 input length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size or pad_len > len(data):
        raise ValueError("invalid PKCS#7 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("invalid PKCS#7 padding bytes")
    return data[:-pad_len]


def _bytes_to_bits_le(data: bytes) -> list[int]:
    bits: list[int] = []
    for b in data:
        for i in range(8):
            bits.append((b >> i) & 1)
    return bits


def _bits_to_bytes_le(bits: list[int]) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for idx, bit in enumerate(bits):
        if bit & 1:
            out[idx // 8] |= 1 << (idx % 8)
    return bytes(out)


def _bits_to_poly(bits: list[int]) -> np.ndarray:
    """Encode up to N bits into a polynomial with coefficients in {0,1}."""
    coeffs = np.zeros(N, dtype=np.int64)
    take = min(N, len(bits))
    if take:
        coeffs[:take] = np.array(bits[:take], dtype=np.int64)
    return coeffs


def _poly_to_bits(poly: np.ndarray, count: int) -> list[int]:
    """Decode first *count* coefficients to bits by nearest of {0, half_q}."""
    count = min(count, N)
    half_q = Q // 2
    out: list[int] = []
    for i in range(count):
        c = int(poly[i]) % Q
        dist_zero = min(c, Q - c)
        dist_one = min(abs(c - half_q), abs(c - (half_q + 1)))
        out.append(1 if dist_one < dist_zero else 0)
    return out


def plaintext_to_message_polys(plaintext: bytes) -> list[np.ndarray]:
    """PKCS#7-pad plaintext, then split into N-bit message polynomials."""
    framed = _pkcs7_pad(plaintext)
    bits = _bytes_to_bits_le(framed)
    blocks = (len(bits) + N - 1) // N
    return [_bits_to_poly(bits[i * N: (i + 1) * N]) for i in range(blocks)]


def message_polys_to_plaintext(msg_polys: list[np.ndarray]) -> bytes:
    if not msg_polys:
        raise ValueError("empty ciphertext (no blocks)")
    bits: list[int] = []
    for poly in msg_polys:
        bits.extend(_poly_to_bits(poly, N))
    framed = _bits_to_bytes_le(bits)
    return _pkcs7_unpad(framed)


# ============================================================
# Cyber
# ============================================================

def keygen():
    A = np.zeros((K, K, N), dtype=np.int64)
    for i in range(K):
        for j in range(K):
            A[i, j] = uniform_poly()

    s = np.array([cbd(ETA1) for _ in range(K)])
    e = np.array([cbd(ETA1) for _ in range(K)])

    t = poly_add(mat_vec_mul(A, s), e)
    return A, t, s


def encrypt_poly(A, t, m):
    r = np.array([cbd(ETA1) for _ in range(K)])
    e1 = np.array([cbd(ETA2) for _ in range(K)])
    e2 = cbd(ETA2)

    A_T = np.transpose(A, (1, 0, 2))
    u = poly_add(mat_vec_mul(A_T, r), e1)

    v = vec_inner(t, r)
    v = poly_add(v, e2)
    half_q = (Q + 1) // 2
    v = poly_add(v, (m * half_q) % Q)
    return u, v


def decrypt_poly(s, u, v):
    noisy = poly_sub(v, vec_inner(s, u))
    return noisy


# ============================================================
# Serialization (raw bytes)
# ============================================================

_MAGIC_PUB = b"CYBP"
_MAGIC_SEC = b"CYBS"
_MAGIC_CTX = b"CYBC"
_BIN_VERSION = 1


def _u16(x: int) -> bytes:
    if not (0 <= x <= 0xFFFF):
        raise ValueError(f"value out of u16 range: {x}")
    return struct.pack("<H", x)


def _u32(x: int) -> bytes:
    if not (0 <= x <= 0xFFFFFFFF):
        raise ValueError(f"value out of u32 range: {x}")
    return struct.pack("<I", x)


def _read_exact(f, n: int) -> bytes:
    data = f.read(n)
    if len(data) != n:
        raise ValueError("unexpected EOF")
    return data


def _pack_header(magic: bytes) -> bytes:
    if Q > 0xFFFF or N > 0xFFFF or K > 0xFF:
        raise ValueError("parameters too large for binary header")
    return magic + bytes([_BIN_VERSION]) + _u16(Q) + _u16(N) + bytes([K])


def _unpack_header(buf: bytes, magic: bytes) -> tuple[int, int, int, int]:
    # returns (version,q,n,k)
    if len(buf) != 10:
        raise ValueError("bad header length")
    if buf[:4] != magic:
        raise ValueError("bad magic")
    version = buf[4]
    q = struct.unpack("<H", buf[5:7])[0]
    n = struct.unpack("<H", buf[7:9])[0]
    k = buf[9]
    return version, q, n, k


def _pack_coeffs_u16(arr: np.ndarray) -> bytes:
    a = np.array(arr, dtype=np.int64) % Q
    if np.any(a < 0) or np.any(a >= Q):
        raise ValueError("coeff out of range after mod")
    return a.astype("<u2", copy=False).tobytes(order="C")


def _unpack_coeffs_u16(buf: bytes, shape: tuple[int, ...]) -> np.ndarray:
    arr = np.frombuffer(buf, dtype="<u2").astype(np.int64, copy=False)
    out = arr.reshape(shape, order="C").astype(np.int64, copy=False)
    return out


def save_pubkey(path, A, t):
    header = _pack_header(_MAGIC_PUB)
    body = _pack_coeffs_u16(A) + _pack_coeffs_u16(t)
    with open(path, "wb") as f:
        f.write(header)
        f.write(body)


def load_pubkey(path):
    with open(path, "rb") as f:
        header = _read_exact(f, 10)
        version, q, n, k = _unpack_header(header, _MAGIC_PUB)
        if version != _BIN_VERSION:
            raise ValueError(f"unsupported pubkey version: {version}")
        if (q, n, k) != (Q, N, K):
            raise ValueError(f"parameter mismatch in pubkey: file has (q,n,k)=({q},{n},{k})")
        a_len = K * K * N * 2
        t_len = K * N * 2
        A = _unpack_coeffs_u16(_read_exact(f, a_len), (K, K, N))
        t = _unpack_coeffs_u16(_read_exact(f, t_len), (K, N))
        leftover = f.read(1)
        if leftover:
            raise ValueError("trailing data in pubkey")
        return A, t


def save_privkey(path, s):
    header = _pack_header(_MAGIC_SEC)
    body = _pack_coeffs_u16(s)
    with open(path, "wb") as f:
        f.write(header)
        f.write(body)


def load_privkey(path):
    with open(path, "rb") as f:
        header = _read_exact(f, 10)
        version, q, n, k = _unpack_header(header, _MAGIC_SEC)
        if version != _BIN_VERSION:
            raise ValueError(f"unsupported privkey version: {version}")
        if (q, n, k) != (Q, N, K):
            raise ValueError(f"parameter mismatch in privkey: file has (q,n,k)=({q},{n},{k})")
        s_len = K * N * 2
        s = _unpack_coeffs_u16(_read_exact(f, s_len), (K, N))
        leftover = f.read(1)
        if leftover:
            raise ValueError("trailing data in privkey")
        return s


def save_ciphertext(path, u_all, v_all):
    u = np.array(u_all, dtype=np.int64)
    v = np.array(v_all, dtype=np.int64)
    if u.ndim != 3 or u.shape[1:] != (K, N):
        raise ValueError(f"bad u shape: {u.shape}")
    if v.ndim != 2 or v.shape[1:] != (N,):
        raise ValueError(f"bad v shape: {v.shape}")
    blocks = u.shape[0]
    if v.shape[0] != blocks:
        raise ValueError("u/v blocks mismatch")

    header = _pack_header(_MAGIC_CTX) + _u32(blocks)
    body = _pack_coeffs_u16(u) + _pack_coeffs_u16(v)
    with open(path, "wb") as f:
        f.write(header)
        f.write(body)


def load_ciphertext(path):
    with open(path, "rb") as f:
        header = _read_exact(f, 10)
        version, q, n, k = _unpack_header(header, _MAGIC_CTX)
        if version != _BIN_VERSION:
            raise ValueError(f"unsupported ciphertext version: {version}")
        if (q, n, k) != (Q, N, K):
            raise ValueError(f"parameter mismatch in ciphertext: file has (q,n,k)=({q},{n},{k})")
        blocks = struct.unpack("<I", _read_exact(f, 4))[0]

        u_len = blocks * K * N * 2
        v_len = blocks * N * 2
        u = _unpack_coeffs_u16(_read_exact(f, u_len), (blocks, K, N))
        v = _unpack_coeffs_u16(_read_exact(f, v_len), (blocks, N))
        leftover = f.read(1)
        if leftover:
            raise ValueError("trailing data in ciphertext")
        return u, v


# ============================================================
# CLI commands
# ============================================================

def cmd_keygen(args):
    A, t, s = keygen()
    save_pubkey(args.pubkey, A, t)
    save_privkey(args.privkey, s)
    if getattr(args, "debug", None):
        os.makedirs(args.debug, exist_ok=True)
        with open(os.path.join(args.debug, "params.txt"), "w") as f:
            f.write(f"q={Q}\n")
            f.write(f"n={N}\n")
            f.write(f"k={K}\n")
            f.write(f"eta1={ETA1}\n")
            f.write(f"eta2={ETA2}\n")
        np.savetxt(os.path.join(args.debug, "A.txt"), A.reshape(-1), fmt="%d")
        np.savetxt(os.path.join(args.debug, "t.txt"), t.reshape(-1), fmt="%d")
        np.savetxt(os.path.join(args.debug, "s.txt"), s.reshape(-1), fmt="%d")
    print(f"Public key  -> {args.pubkey}")
    print(f"Private key -> {args.privkey}")


def cmd_encrypt(args):
    A, t = load_pubkey(args.pubkey)
    plaintext = open(args.input, "rb").read()

    u_blocks, v_blocks = [], []
    msg_polys = plaintext_to_message_polys(plaintext)
    for m in msg_polys:
        u, v = encrypt_poly(A, t, m)
        u_blocks.append(u)
        v_blocks.append(v)

    save_ciphertext(args.output, u_blocks, v_blocks)
    if getattr(args, "debug", None):
        os.makedirs(args.debug, exist_ok=True)
        with open(os.path.join(args.debug, "meta.txt"), "w") as f:
            f.write(f"plaintext_bytes={len(plaintext)}\n")
            f.write(f"blocks={len(msg_polys)}\n")
    print(f"Encrypted {len(plaintext)} bytes ({len(msg_polys)} blocks) -> {args.output}")


def cmd_decrypt(args):
    s = load_privkey(args.privkey)
    u_all, v_all = load_ciphertext(args.input)

    msg_polys: list[np.ndarray] = []
    for i in range(len(u_all)):
        msg_polys.append(decrypt_poly(s, u_all[i], v_all[i]))

    plaintext = message_polys_to_plaintext(msg_polys)
    open(args.output, "wb").write(plaintext)
    if getattr(args, "debug", None):
        os.makedirs(args.debug, exist_ok=True)
        with open(os.path.join(args.debug, "meta.txt"), "w") as f:
            f.write(f"plaintext_bytes={len(plaintext)}\n")
            f.write(f"blocks={len(msg_polys)}\n")
    print(f"Decrypted {len(plaintext)} bytes ({len(msg_polys)} blocks) -> {args.output}")


def main():
    parser = argparse.ArgumentParser(description="Cyber cipher")
    sub = parser.add_subparsers(dest="command", required=True)

    kg = sub.add_parser("keygen", help="Generate public/private key pair")
    kg.add_argument("--pubkey", required=True, help="Output path for public key (.pub)")
    kg.add_argument("--privkey", required=True, help="Output path for private key (extensionless)")
    kg.add_argument("--debug", help="Directory for debug / intermediate files")

    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("--pubkey", required=True, help="Path to public key (.pub)")
    enc.add_argument("--input", required=True, help="Plaintext file to encrypt")
    enc.add_argument("--output", required=True, help="Output ciphertext path (.enc)")
    enc.add_argument("--debug", help="Directory for debug / intermediate files")

    dec = sub.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("--privkey", required=True, help="Path to private key (extensionless)")
    dec.add_argument("--input", required=True, help="Ciphertext file (.enc)")
    dec.add_argument("--output", required=True, help="Output decrypted file path")
    dec.add_argument("--debug", help="Directory for debug / intermediate files")

    args = parser.parse_args()
    {"keygen": cmd_keygen, "encrypt": cmd_encrypt, "decrypt": cmd_decrypt}[args.command](args)


if __name__ == "__main__":
    main()
