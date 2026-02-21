#!/usr/bin/env sage
from sage.all import CyclotomicField, GF, ZZ, identity_matrix, matrix, block_matrix
from fpylll import IntegerMatrix, LLL, BKZ

from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


K.<zeta256> = CyclotomicField(256)
n = 128


def parse_output(path="output.txt"):
    txt = open(path, "r").read().replace("^", "**")
    lines = [ln.strip() for ln in txt.splitlines() if ln.strip()]
    env = {"zeta256": zeta256, "K": K}
    for ln in lines[:4]:
        exec(ln, env, env)
    return env["iv"], env["enc"], env["q0"], env["q1"], env["q2"], env["s0"], env["s1"], env["s2"]


iv_hex, enc_hex, q0, q1, q2, s0, s1, s2 = parse_output()


def conj_matrix(n_):
    J = matrix(ZZ, n_, n_)
    J[0, 0] = 1
    for j in range(1, n_):
        J[j, n_ - j] = -1
    return J


def mult_matrix_mod(elem, p):
    coeffs = list(elem)
    if len(coeffs) < n:
        coeffs += [0] * (n - len(coeffs))
    Fp = GF(p)
    M = matrix(Fp, n, n)
    for j in range(n):
        for k in range(n):
            idx = j + k
            if idx < n:
                M[idx, j] += Fp(coeffs[k])
            else:
                M[idx - n, j] -= Fp(coeffs[k])
    return M


def center_lift(x, p):
    x = int(x) % p
    return x if x <= p // 2 else x - p


def build_lattice_fg(p):
    # Derived relation: f*(q0*s2 - 1) = q0*s1*g + bar(q1)*bar(g)
    c1 = q0 * s2 - 1
    c2 = q0 * s1
    c3 = q1.conjugate()

    Fp = GF(p)
    M1 = mult_matrix_mod(c1, p)
    if M1.determinant() == 0:
        raise ValueError("c1 not invertible mod p")
    M2 = mult_matrix_mod(c2, p)
    M3 = mult_matrix_mod(c3, p)
    Jp = conj_matrix(n).change_ring(Fp)

    # Column convention: f_vec = H * g_vec (mod p)
    H = M1.inverse() * (M2 + M3 * Jp)
    H_int = matrix(ZZ, n, n, [center_lift(v, p) for v in H.list()])

    # Row basis for lattice vectors (f | g):
    # (k, g) -> (p*k + g*H^T, g)
    B = block_matrix([
        [p * identity_matrix(ZZ, n), matrix(ZZ, n, n)],
        [H_int.transpose(), identity_matrix(ZZ, n)],
    ])

    A = IntegerMatrix(2 * n, 2 * n)
    for i in range(2 * n):
        for j in range(2 * n):
            A[i, j] = int(B[i, j])
    return A


def compute_FG_from_f_g(f, g):
    F = (f * q1 - g.conjugate()) / q0
    G = (g * q1 + f.conjugate()) / q0
    return F, G


def verify_candidate(f, g):
    if f * f.conjugate() + g * g.conjugate() != q0:
        return False
    F, G = compute_FG_from_f_g(f, g)
    if F.conjugate() * F + G.conjugate() * G != q2:
        return False
    if g * g.conjugate() + G * G.conjugate() != s2:
        return False
    if f * g.conjugate() + F * G.conjugate() != s1:
        return False
    return True


def decrypt_with_unit_search(f, g):
    F, G = compute_FG_from_f_g(f, g)
    iv_b = bytes.fromhex(iv_hex)
    ct_b = bytes.fromhex(enc_hex)

    for k in range(256):
        u = zeta256**k
        sk = (u * f, u * g, u * F, u * G)
        key = sha256(str(sk).encode()).digest()
        pt = AES.new(key=key, mode=AES.MODE_CBC, iv=iv_b).decrypt(ct_b)
        try:
            msg = unpad(pt, 16).decode()
        except Exception:
            continue
        if "0xfun{" in msg:
            return msg
    return None


def scan_basis(A, coeff_bound=80):
    for i in range(2 * n):
        v = [int(A[i, j]) for j in range(2 * n)]
        f_vec = v[:n]
        g_vec = v[n:]
        if max(max(abs(x) for x in f_vec), max(abs(x) for x in g_vec)) > coeff_bound:
            continue
        f = K(f_vec)
        g = K(g_vec)
        if not verify_candidate(f, g):
            continue
        return decrypt_with_unit_search(f, g)
    return None


def main():
    assert q0 * q2 - q1 * q1.conjugate() == 1
    assert s0 * s2 - s1 * s1.conjugate() == 1
    assert q0 + q2 == s0 + s2

    for p in [65537, 131071, 262139]:
        print(f"[+] p={p}")
        A = build_lattice_fg(p)

        LLL.reduction(A, method="fast", float_type="dd")
        flag = scan_basis(A)
        if flag:
            print(flag)
            return

        par = BKZ.Param(block_size=40, max_loops=1, flags=BKZ.MAX_LOOPS, auto_abort=True, gh_factor=True)
        BKZ.reduction(A, par, float_type="dd")
        flag = scan_basis(A)
        if flag:
            print(flag)
            return

    print("[-] Not found")


if __name__ == "__main__":
    main()