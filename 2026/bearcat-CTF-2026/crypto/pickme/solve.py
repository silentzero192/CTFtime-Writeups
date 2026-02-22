#!/usr/bin/env python3
import argparse
import base64
import re
import socket

from Crypto.Util.number import GCD, getPrime, long_to_bytes


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_int(x: int) -> bytes:
    if x < 0:
        raise ValueError("Only non-negative INTEGER values are used here")
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + der_len(len(b)) + b


def build_malicious_key(e: int = 65537):
    while True:
        p = getPrime(512)
        if p != e and GCD(e, p - 1) == 1:
            break

    q = p
    n = p * q

    # Matches server's incorrect assumption when p == q.
    fake_phi = (p - 1) * (q - 1)
    d_fake = pow(e, -1, fake_phi)

    # Not validated by server, can be arbitrary when p == q.
    iqmp = 1

    fields = [
        0,
        n,
        e,
        d_fake,
        p,
        q,
        d_fake % (p - 1),
        d_fake % (q - 1),
        iqmp,
    ]

    content = b"".join(der_int(v) for v in fields)
    der = b"\x30" + der_len(len(content)) + content
    b64 = base64.b64encode(der)
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    pem = (
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        + b"\n".join(lines)
        + b"\n-----END RSA PRIVATE KEY-----\n"
    )

    # Correct exponent for n = p^2
    d_real = pow(e, -1, p * (p - 1))
    return pem, n, d_real


def recv_until_prompt(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def run(host: str, port: int):
    pem, n, d_real = build_malicious_key()

    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(5)
        transcript = recv_until_prompt(sock, b"Enter your key in pem format:")
        sock.sendall(pem)

        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            transcript += chunk

    text = transcript.decode(errors="ignore")
    match = re.search(
        r"Some unknown error occurred! Maybe you should take a look: (\d+)", text
    )
    if not match:
        raise RuntimeError(f"Leak not found. Full server response:\n{text}")

    c = int(match.group(1))
    m = pow(c, d_real, n)
    raw = long_to_bytes(m)

    flag_match = re.search(rb"BCCTF\{[^}]+\}", raw)
    if flag_match:
        return flag_match.group(0).decode()
    return raw.decode(errors="ignore")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="chal.bearcatctf.io")
    parser.add_argument("--port", type=int, default=56025)
    args = parser.parse_args()

    flag = run(args.host, args.port)
    print(flag)


if __name__ == "__main__":
    main()
