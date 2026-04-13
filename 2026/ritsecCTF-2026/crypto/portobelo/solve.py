import json
import socket
from Crypto.Cipher import AES
import hashlib


HOST = "portobelo.ctf.ritsec.club"
PORT = 1337


with open("params.json") as f:
    PARAMS = json.load(f)


P = int(PARAMS["p"])
PRIMES = [int(x) for x in PARAMS["primes"]]
BASE_A = int(PARAMS["base_curve_A"])
ISO_CHALLENGE_A = int(PARAMS["iso_challenge_A"])
GR48_POLY = [int(x) for x in PARAMS["gr48_poly"]]
GR48_GEN = [int(x) for x in PARAMS["gr48_generator"]]
FLAG_CT = bytes.fromhex(PARAMS["flag_ct"])
FLAG_NONCE = bytes.fromhex(PARAMS["flag_nonce"])
FLAG_TAG = bytes.fromhex(PARAMS["flag_tag"])


def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data


def query_service(xs):
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        banner = recv_until(sock, b"READY\n").decode()
        print(banner, end="")

        traces = []
        ops_count = None
        for x in xs:
            sock.sendall(f"QUERY {x}\n".encode())
            line = b""
            while not line.endswith(b"\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    raise EOFError("connection closed during query")
                line += chunk
            parts = line.decode().strip().split()
            if len(parts) != 4 or parts[0] != "RESULT":
                raise ValueError(f"unexpected response: {line!r}")
            _, _, ops_raw, trace_raw = parts
            if ops_count is None:
                ops_count = int(ops_raw)
            elif ops_count != int(ops_raw):
                raise ValueError("ops_count changed across queries")
            traces.append(int(trace_raw))

        sock.sendall(b"QUIT\n")
    return traces, ops_count


def solve_linear_system_mod(matrix, rhs, mod):
    n = len(matrix)
    aug = [row[:] + [rhs_i] for row, rhs_i in zip(matrix, rhs)]

    for col in range(n):
        pivot = None
        for row in range(col, n):
            if aug[row][col] % mod != 0:
                pivot = row
                break
        if pivot is None:
            raise ValueError("singular matrix")
        if pivot != col:
            aug[col], aug[pivot] = aug[pivot], aug[col]

        inv = pow(aug[col][col], -1, mod)
        aug[col] = [(value * inv) % mod for value in aug[col]]

        for row in range(n):
            if row == col or aug[row][col] == 0:
                continue
            factor = aug[row][col]
            aug[row] = [
                (lhs - factor * rhs_val) % mod
                for lhs, rhs_val in zip(aug[row], aug[col])
            ]

    return [aug[row][-1] % mod for row in range(n)]


def to_small_signed(value, mod):
    return value if value <= mod // 2 else value - mod


def xdbl(X, Z, A24, p):
    XX = (X * X) % p
    ZZ = (Z * Z) % p
    XZ = (X * Z) % p
    X2 = (XX - ZZ) * (XX - ZZ) % p
    t = (XX + ZZ) % p
    Z2 = (4 * XZ * (t + (4 * A24 - 2) * XZ)) % p
    return X2 % p, Z2 % p


def xadd(X1, Z1, X2, Z2, Xd, Zd, p):
    U = (X1 - Z1) * (X2 + Z2) % p
    V = (X1 + Z1) * (X2 - Z2) % p
    add = (U + V) % p
    sub = (U - V) % p
    X3 = Zd * add * add % p
    Z3 = Xd * sub * sub % p
    return X3, Z3


def xmul(x0, k, A, p):
    if k == 0:
        return None
    A24 = (A + 2) * pow(4, -1, p) % p
    X0, Z0 = 1, 0
    X1, Z1 = x0 % p, 1

    bits = k.bit_length()
    for i in range(bits - 1, -1, -1):
        if (k >> i) & 1:
            X0, Z0 = xadd(X0, Z0, X1, Z1, x0, 1, p)
            X1, Z1 = xdbl(X1, Z1, A24, p)
        else:
            X1, Z1 = xadd(X0, Z0, X1, Z1, x0, 1, p)
            X0, Z0 = xdbl(X0, Z0, A24, p)

    if Z0 == 0:
        return None
    return X0 * pow(Z0, -1, p) % p


def velu(kernel_x, ell, A, p):
    inv = lambda x: pow(x % p, -1, p)

    A %= p
    kernel_xs = [kernel_x % p]

    if ell >= 5:
        A24 = (A + 2) * pow(4, -1, p) % p
        X2, Z2 = xdbl(kernel_x % p, 1, A24, p)
        if Z2 != 0:
            kernel_xs.append(X2 * inv(Z2) % p)

        for _ in range(3, (ell + 1) // 2):
            if len(kernel_xs) < 2:
                break
            Xprev, Xprev2 = kernel_xs[-1], kernel_xs[-2]
            Xnew, Znew = xadd(Xprev, 1, kernel_xs[0], 1, Xprev2, 1, p)
            if Znew == 0:
                break
            kernel_xs.append(Xnew * inv(Znew) % p)

    sigma = 0
    for xk in kernel_xs:
        if xk == 0:
            continue
        fprime = (3 * xk * xk + 2 * A * xk + 1) % p
        fdprime = (6 * xk + 2 * A) % p
        if fprime != 0:
            sigma = (sigma + fdprime * inv(fprime)) % p

    return (A - 12 * sigma) % p


def group_action(input_A, secret_key, small_primes, p):
    remaining = list(secret_key)
    A_int = input_A % p

    for outer_iter in range(400):
        if not any(r != 0 for r in remaining):
            break

        x_try = outer_iter + 1
        rhs = (pow(x_try, 3, p) + A_int * pow(x_try, 2, p) + x_try) % p
        if rhs == 0:
            continue

        leg = pow(rhs, (p - 1) // 2, p)
        if leg == 1:
            sign = 1
        elif leg == p - 1:
            sign = -1
        else:
            continue

        made_progress = False
        for i, ell in enumerate(small_primes):
            if remaining[i] == 0:
                continue
            if not ((remaining[i] > 0 and sign == 1) or (remaining[i] < 0 and sign == -1)):
                continue

            cofactor = (p + 1) // ell
            kernel_x = xmul(x_try, cofactor, A_int, p)
            if kernel_x is None:
                continue

            check = xmul(kernel_x, ell, A_int, p)
            if check is not None:
                continue

            new_A = velu(kernel_x, ell, A_int, p)
            A_int = new_A % p
            if remaining[i] > 0:
                remaining[i] -= 1
            else:
                remaining[i] += 1
            made_progress = True

        if not made_progress and outer_iter > 100:
            x_try = (x_try * 3 + 7) % p
            if x_try == 0:
                x_try = 1

    return A_int


def mul(a, b, poly):
    deg = 8
    prod = [0] * (2 * deg - 1)
    for i in range(deg):
        for j in range(deg):
            prod[i + j] = (prod[i + j] + a[i] * b[j]) % 4

    for d in range(2 * deg - 2, deg - 1, -1):
        if prod[d] != 0:
            coeff = prod[d]
            for k in range(deg + 1):
                prod[d - deg + k] = (prod[d - deg + k] - coeff * poly[k]) % 4
            prod[d] = 0
    return prod[:deg]


def kdf(secret_key, poly_coeffs, gen_coeffs):
    sk_bytes = bytes([e + 127 for e in secret_key])
    h = hashlib.shake_256(sk_bytes)
    state_bytes = h.digest(136)

    mixed = bytearray()
    for off in range(0, len(state_bytes), 8):
        block = state_bytes[off:off + 8]
        if len(block) < 8:
            block = block + bytes(8 - len(block))

        elem = [int(b) % 4 for b in block]
        product = mul(elem, gen_coeffs, poly_coeffs)
        mixed.extend(bytes(c % 256 for c in product))

    squeeze = h.digest(32)
    derived = hashlib.shake_256(bytes(mixed)).digest(32)
    return bytes(a ^ b for a, b in zip(derived, squeeze))


def main():
    xs = [x for x in range(len(PRIMES) + 1) if x != 2]
    traces, ops_count = query_service(xs)

    matrix = []
    for x in xs:
        row = []
        cur = 1
        for _ in range(len(PRIMES)):
            row.append(cur)
            cur = (cur * x) % P
        matrix.append(row)

    coeffs_mod = solve_linear_system_mod(matrix, traces, P)
    coeffs = [to_small_signed(value, P) for value in coeffs_mod]

    missing_abs = ops_count - sum(abs(value) for value in coeffs)
    zeros = [i for i, value in enumerate(coeffs) if value == 0]

    print(f"ops_count = {ops_count}")
    print(f"missing_abs = {missing_abs}")
    print(f"zero coefficient indices = {zeros}")

    recovered = None
    flag = None
    for idx in zeros:
        for value in (-missing_abs, missing_abs):
            if missing_abs == 0 and value < 0:
                continue
            trial = coeffs[:]
            trial[idx] = value
            key = kdf(trial, GR48_POLY, GR48_GEN)
            cipher = AES.new(key, AES.MODE_GCM, nonce=FLAG_NONCE)
            try:
                candidate_flag = cipher.decrypt_and_verify(FLAG_CT, FLAG_TAG)
                recovered = trial
                flag = candidate_flag
                print(f"matched poisoned index {idx} with value {trial[idx]}")
                break
            except ValueError:
                continue
        if recovered is not None:
            break

    if recovered is None:
        raise RuntimeError("failed to recover secret key from ciphertext candidates")

    print(flag.decode())


if __name__ == "__main__":
    main()
