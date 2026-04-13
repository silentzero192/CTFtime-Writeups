#!/usr/bin/env python3
"""Automates the Sloppy Sauce crypto lab: calibrate curves, CRT the scalar, submit, and print the flag."""
import re
import socket
from dataclasses import dataclass
from typing import List, Tuple

HOST = 'sloppysauce.codevinci.it'
PORT = 9976
P = 40009
LEGACY_CANARY = '325'
BUFFER = 4096

@dataclass
class CurveConfig:
    a: int
    b: int
    Gx: int
    Gy: int
    order: int | None = None
    Q: Tuple[int, int] | None = None

    def __repr__(self) -> str:
        return f'Curve(a={self.a}, b={self.b}, G=({self.Gx},{self.Gy}))'

CURVES: List[CurveConfig] = [
    CurveConfig(a=28743, b=26442, Gx=24690, Gy=8544),
    CurveConfig(a=39776, b=12479, Gx=28118, Gy=32521),
    CurveConfig(a=6055, b=39873, Gx=17594, Gy=2402),
    CurveConfig(a=5449, b=36215, Gx=39502, Gy=8861),
    CurveConfig(a=17566, b=32517, Gx=36528, Gy=23367),
    CurveConfig(a=5971, b=13529, Gx=6308, Gy=30023),
]


def send_line(conn: socket.socket, line: str) -> None:
    conn.sendall((line + '\n').encode())


def recv_until(conn: socket.socket,
               marker: bytes = b'Choice > ') -> bytes:
    """Read until the marker string is seen."""
    buf = bytearray()
    while marker not in buf:
        chunk = conn.recv(BUFFER)
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def ec_add(Pt: Tuple[int, int] | None,
           Qt: Tuple[int, int] | None,
           a: int) -> Tuple[int, int] | None:
    if Pt is None:
        return Qt
    if Qt is None:
        return Pt
    x1, y1 = Pt
    x2, y2 = Qt
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if Pt == Qt:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def compute_order(curve: CurveConfig) -> int:
    G = (curve.Gx, curve.Gy)
    R = G
    count = 1
    while True:
        R = ec_add(R, G, curve.a)
        count += 1
        if R is None:
            return count
        if count > 100_000:
            raise RuntimeError('order search exceeds limit')


def discrete_log(curve: CurveConfig) -> int:
    target = curve.Q
    if target is None:
        raise ValueError('missing Q for discrete log')
    G = (curve.Gx, curve.Gy)
    limit = curve.order
    R = G
    k = 1
    while True:
        if R == target:
            return k
        R = ec_add(R, G, curve.a)
        k += 1
        if limit and k > limit:
            raise RuntimeError('discrete log exceeds order')


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def crt(congruences: List[Tuple[int, int]]) -> Tuple[int, int]:
    x = 0
    mod = 1
    for m, r in congruences:
        g = gcd(mod, m)
        if (r - x) % g:
            raise RuntimeError('inconsistent congruences')
        m_div = m // g
        inv = pow((mod // g) % m_div, -1, m_div)
        t = ((r - x) // g * inv) % m_div
        x += mod * t
        mod *= m_div
        x %= mod
    return x, mod


def parse_point(block: str) -> Tuple[int, int]:
    match = re.search(r'Q = \((\d+), (\d+)\)', block)
    if not match:
        raise ValueError('Q point not found in server response')
    return int(match.group(1)), int(match.group(2))


def calibrate_curve(conn: socket.socket, curve: CurveConfig) -> None:
    print(f'[*] calibrating {curve}')
    send_line(conn, '2')
    recv_until(conn, b'legacy_canary?> ')
    send_line(conn, LEGACY_CANARY)
    recv_until(conn, b'Provide:')
    send_line(conn, f'{P} {curve.a} {curve.b} {curve.Gx} {curve.Gy}')
    block = recv_until(conn, b'Choice > ') .decode(errors='ignore')
    curve.Q = parse_point(block)
    print(f'    -> Q = {curve.Q}')


def submit_scalar(conn: socket.socket, scalar: int) -> str:
    send_line(conn, '4')
    recv_until(conn, b'legacy_canary?> ')
    send_line(conn, LEGACY_CANARY)
    recv_until(conn, b'candidate scalar d = ')
    send_line(conn, str(scalar))
    response = recv_until(conn, b'Choice > ').decode(errors='ignore')
    flag_match = re.search(r'(CodeVinci\{[^}]+\})', response)
    if not flag_match:
        raise RuntimeError('flag not found in server response')
    return flag_match.group(1)


def main() -> None:
    with socket.create_connection((HOST, PORT), timeout=10) as conn:
        print('[*] connected, waiting for menu...')
        recv_until(conn, b'Choice > ')
        for curve in CURVES:
            calibrate_curve(conn, curve)
        print('[*] computing discrete logs and CRT...')
        congruences: List[Tuple[int, int]] = []
        for curve in CURVES:
            curve.order = compute_order(curve)
            log_value = discrete_log(curve)
            congruences.append((curve.order, log_value))
            print(f'    * order {curve.order}, log = {log_value}')
        combined, modulus = crt(congruences)
        scalar_64 = combined % (1 << 64)
        print(f'[+] combined scalar ≡ {combined} mod {modulus}')
        print(f'[+] reduced 64-bit scalar = {scalar_64}')
        flag = submit_scalar(conn, scalar_64)
        print('[+] flag:', flag)


if __name__ == '__main__':
    main()
