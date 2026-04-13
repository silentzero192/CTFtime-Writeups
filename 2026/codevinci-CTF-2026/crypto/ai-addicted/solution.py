#!/usr/bin/env python3
import socket
import re
from itertools import combinations
from math import prod
from sympy import Matrix, Poly, symbols

P = (1 << 61) - 1
E = (1 << 521) - 1
HOST = "addicted.codevinci.it"
PORT = 9978
INV_E_FP = pow(E, -1, P - 1)
INV_E_FP2 = pow(E, -1, P * P - 1)
INV2 = pow(2, -1, P)

LAMBDA = symbols("lambda")


class Fp2:
    """Represents a + b·√D over Fₚ where √D is a non-square root."""

    def __init__(self, a: int, b: int, D: int):
        self.D = D % P
        self.a = a % P
        self.b = b % P

    def __add__(self, other):
        self._check(other)
        return Fp2(self.a + other.a, self.b + other.b, self.D)

    def __neg__(self):
        return Fp2(-self.a, -self.b, self.D)

    def __sub__(self, other):
        return self + (-other)

    def __mul__(self, other):
        self._check(other)
        a, b, c, d = self.a, self.b, other.a, other.b
        return Fp2(a * c + b * d * self.D, a * d + b * c, self.D)

    def pow(self, exponent: int):
        exponent %= (P * P - 1)
        result = Fp2(1, 0, self.D)
        base = Fp2(self.a, self.b, self.D)
        while exponent:
            if exponent & 1:
                result = result * base
            base = base * base
            exponent >>= 1
        return result

    def _check(self, other):
        if not isinstance(other, Fp2):
            raise TypeError("Both operands must be Fp2")
        if self.D != other.D:
            raise ValueError("Mismatched quadratic extensions")

    def to_int(self):
        if self.b != 0:
            raise ValueError("Not purely in base field")
        return self.a % P


class CTFSess:
    def __init__(self):
        self.sock = socket.create_connection((HOST, PORT))
        self.sock.settimeout(2.0)
        self.buffer = b""

    def recv_until_prompt(self) -> str:
        marker = b"> "
        while marker not in self.buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            self.buffer += chunk
        idx = self.buffer.index(marker) + len(marker)
        data = self.buffer[:idx]
        self.buffer = self.buffer[idx:]
        return data.decode()

    def send_vector(self, vector):
        payload = " ".join(map(str, vector)).encode() + b"\n"
        self.sock.sendall(payload)
        return self.recv_until_prompt()

    def recv_all(self, timeout=1.0):
        self.sock.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data.decode()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def parse_result_chunk(text):
    match = re.search(r"Result:\s*\[([^]]+)\]", text)
    if not match:
        raise ValueError("Result line not found")
    values = [int(x.strip()) for x in match.group(1).split(",")]
    if len(values) != 4:
        raise ValueError("Expected 4 integers")
    return values


def collect_matrix_columns():
    session = CTFSess()
    try:
        session.recv_until_prompt()  # consume welcome & first prompt
        basis_vectors = [(1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)]
        columns = []
        for vec in basis_vectors:
            chunk = session.send_vector(vec)
            columns.append(parse_result_chunk(chunk))
        return columns, session
    except Exception:
        session.close()
        raise


def factor_roots(matrix_columns):
    matrix = Matrix([[matrix_columns[col][row] for col in range(4)] for row in range(4)])
    poly = Poly(matrix.charpoly().as_expr(), LAMBDA, modulus=P)
    _, factors = poly.factor_list()
    roots = []
    D_value = None

    for factor, multiplicity in factors:
        degree = factor.degree()
        coeffs = [int(c) % P for c in factor.all_coeffs()]
        if degree == 1:
            root = (-coeffs[1]) % P
            val = pow(root, INV_E_FP, P)
            roots.extend([val] * multiplicity)
        elif degree == 2:
            A = coeffs[1]
            B = coeffs[2]
            D = (A * A - 4 * B) % P
            if D == 0:
                root = (-A * INV2) % P
                root_val = pow(root, INV_E_FP, P)
                roots.extend([root_val] * (2 * multiplicity))
                continue
            if D_value is None:
                D_value = D
            elif D_value != D:
                raise ValueError("Multiple, inconsistent quadratic extensions")
            base = (-A * INV2) % P
            sqrt_coeff = INV2
            plus = Fp2(base, sqrt_coeff, D_value)
            minus = Fp2(base, (-sqrt_coeff) % P, D_value)
            plus_pow = plus.pow(INV_E_FP2)
            minus_pow = minus.pow(INV_E_FP2)
            for _ in range(multiplicity):
                roots.append(plus_pow)
                roots.append(minus_pow)
        else:
            raise ValueError(f"Unsupported factor degree {degree}")

    if len(roots) != 4:
        raise ValueError("Expected exactly four roots")
    return roots, D_value


def compute_coefficients(roots, D_value):
    if D_value is None:
        roots_field = [r % P for r in roots]
        zero = 0
        one = 1

        def add(a, b): return (a + b) % P
        def mul(a, b): return (a * b) % P
        def neg(x): return (-x) % P
    else:
        roots_field = []
        zero = Fp2(0, 0, D_value)
        one = Fp2(1, 0, D_value)

        for root in roots:
            if isinstance(root, Fp2):
                if root.D != D_value:
                    raise ValueError("Root uses wrong quadratic extension")
                roots_field.append(root)
            else:
                roots_field.append(Fp2(root, 0, D_value))

        def add(a, b): return a + b
        def mul(a, b): return a * b
        def neg(x): return -x

    s1 = zero
    for root in roots_field:
        s1 = add(s1, root)

    s2 = zero
    for a, b in combinations(roots_field, 2):
        s2 = add(s2, mul(a, b))

    s3 = zero
    for a, b, c in combinations(roots_field, 3):
        s3 = add(s3, mul(mul(a, b), c))

    s4 = one
    for root in roots_field:
        s4 = mul(s4, root)

    c0 = s1
    c1 = neg(s2)
    c2 = s3
    c3 = neg(s4)

    def to_int(value):
        if D_value is None:
            return value % P
        if not isinstance(value, Fp2):
            raise ValueError("Expected Fp2 value")
        return value.to_int()

    return to_int(c0), to_int(c1), to_int(c2), to_int(c3)


def submit_secrets(session, secrets):
    payload = " ".join(str(x) for x in secrets).encode() + b"\n"
    session.sock.sendall(payload)
    return session.recv_all()


def main():
    columns, session = collect_matrix_columns()
    try:
        roots, D_value = factor_roots(columns)
        secrets = compute_coefficients(roots, D_value)
        response = submit_secrets(session, secrets)
        print("Computed secrets:", secrets)
        print("Server response:")
        print(response.strip())
    finally:
        session.close()


if __name__ == "__main__":
    main()
