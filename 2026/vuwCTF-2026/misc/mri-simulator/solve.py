#!/usr/bin/env python3
"""
VuwCTF 2026 - misc/MRI SIMULATOR 1999
Flag: VuwCTF{wires_overhead}

The remote service is a k-space sampler. You send it "x,y" coordinates into a
128x128 grid and it hands back the complex Fourier coefficient of a hidden
image at that point -- which is exactly what an MRI scanner acquires. Collect
the whole grid, run an inverse 2-D FFT, and the image falls out.

Two things make this fast:

  * The "| Positioning..." delay is a fixed ~7s buffering cost, not a per-query
    one. Blasting every query down a single socket without waiting for replies
    pulls all 16384 points in well under a minute.
  * The image is real-valued, so k-space is Hermitian:
        F(x, y) == conj(F(N-x, N-y))
    Only half the grid actually needs to be requested.

Usage:
    python3 solve.py                  # half grid via Hermitian symmetry (default)
    python3 solve.py --full           # request all 16384 points
    python3 solve.py --replay k.txt   # reconstruct from a saved capture
"""

import argparse
import re
import socket
import sys
import threading
import time

import numpy as np

HOST = "mri-simulator-onenineninenine.challenges.2026.vuwctf.com"
PORT = 9976
N = 128

# "| Value is -39.28278530812878 + 7.980561937987545i"
VALUE_RE = re.compile(rb"Value is\s*(-?[\d.eE+-]+)\s*\+\s*(-?[\d.eE+-]+)i")


def half_grid(n=N):
    """Coordinates covering k-space up to Hermitian symmetry.

    F(x, y) == conj(F(-x, -y)), and here the grid is fftshift-centred so the
    origin sits at (n//2, n//2). Walking rows 0..n//2 and taking the full row
    only on the centre line covers every conjugate pair exactly once, plus the
    four self-conjugate points.
    """
    c = n // 2
    pts = []
    for x in range(c + 1):
        for y in range(n):
            if x == c and y > c:
                break  # second half of the centre row is the mirror of the first
            pts.append((x, y))
    return pts


def full_grid(n=N):
    return [(x, y) for x in range(n) for y in range(n)]


def scan(points, host=HOST, port=PORT, verbose=True):
    """Pipeline every coordinate down one socket and collect the replies."""
    sock = socket.create_connection((host, port), timeout=20)
    sock.settimeout(180)

    payload = b"".join(b"%d,%d\n" % p for p in points)

    def send_all():
        # Drip-feed so we never wedge on a full send buffer while the server is
        # still sitting on its startup delay.
        try:
            for i in range(0, len(payload), 8192):
                sock.sendall(payload[i:i + 8192])
        except OSError:
            pass

    threading.Thread(target=send_all, daemon=True).start()

    want = len(points)
    buf = bytearray()
    start = time.time()
    reported = 0
    while buf.count(b"Value is") < want:
        chunk = sock.recv(1 << 20)
        if not chunk:
            break
        buf += chunk
        got = buf.count(b"Value is")
        if verbose and got - reported >= 2000:
            reported = got
            print(f"[*] {got}/{want} samples  ({time.time() - start:.1f}s)", file=sys.stderr)
    sock.close()

    got = buf.count(b"Value is")
    if verbose:
        print(f"[+] {got}/{want} samples in {time.time() - start:.1f}s", file=sys.stderr)
    if got < want:
        raise RuntimeError(f"short read: got {got} of {want} samples")
    return bytes(buf)


def parse(raw):
    """Pull the complex values out of the transcript, in reply order."""
    return [complex(float(re_), float(im)) for re_, im in VALUE_RE.findall(raw)]


def build_kspace(points, values, n=N):
    """Place the samples, filling unmeasured points by conjugate symmetry."""
    if len(values) != len(points):
        raise ValueError(f"{len(points)} coordinates sent but {len(values)} values returned")

    K = np.zeros((n, n), dtype=complex)
    seen = np.zeros((n, n), dtype=bool)
    c = n // 2
    for (x, y), v in zip(points, values):
        K[x, y] = v
        seen[x, y] = True
        # Mirror through the k-space origin at (c, c).
        mx, my = (2 * c - x) % n, (2 * c - y) % n
        if not seen[mx, my]:
            K[mx, my] = v.conjugate()
            seen[mx, my] = True

    if not seen.all():
        raise RuntimeError(f"{(~seen).sum()} k-space points never filled")
    return K


def reconstruct(K):
    """Inverse 2-D FFT. The grid is fftshift-centred, so undo that first.

    No fftshift on the *output* -- adding one wraps the picture and splits the
    flag across swapped quadrants.
    """
    img = np.fft.ifft2(np.fft.ifftshift(K))
    resid = np.abs(img.imag).max()
    scale = np.abs(img.real).max()
    print(f"[*] residual imaginary part: {resid:.3e} (vs real max {scale:.2f})", file=sys.stderr)
    if resid > 1e-6 * max(scale, 1.0):
        print("[!] large imaginary residual -- shift convention may be wrong", file=sys.stderr)
    return img.real


def save_png(img, path, size=640):
    a = img - img.min()
    peak = a.max()
    if peak:
        a = a / peak
    a = (a * 255).astype(np.uint8)
    try:
        from PIL import Image
    except ImportError:
        np.save(path.rsplit(".", 1)[0] + ".npy", img)
        print("[!] Pillow missing; wrote raw .npy instead", file=sys.stderr)
        return
    Image.fromarray(a).resize((size, size), Image.LANCZOS).save(path)
    print(f"[+] wrote {path}", file=sys.stderr)


def ascii_preview(img, cols=110, rows=44):
    """Rough terminal render, for when you have no image viewer handy."""
    ramp = "@%#*+=-:. "  # dark -> light; the scan is dark ink on light paper
    h, w = img.shape
    a = img - img.min()
    if a.max():
        a = a / a.max()
    out = []
    for r in range(rows):
        line = []
        for c in range(cols):
            block = a[r * h // rows:(r + 1) * h // rows, c * w // cols:(c + 1) * w // cols]
            v = block.mean() if block.size else 0.0
            line.append(ramp[min(len(ramp) - 1, int(v * len(ramp)))])
        out.append("".join(line))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--full", action="store_true", help="request all 16384 points instead of half")
    ap.add_argument("--replay", metavar="FILE", help="reconstruct from a saved transcript")
    ap.add_argument("--save-raw", metavar="FILE", default="kspace.txt", help="where to store the transcript")
    ap.add_argument("--out", default="flag.png")
    ap.add_argument("--ascii", action="store_true", help="also dump a terminal preview")
    args = ap.parse_args()

    if args.replay:
        raw = open(args.replay, "rb").read()
        values = parse(raw)
        # Infer which grid the capture used from how many values it holds.
        for points in (full_grid(), half_grid()):
            if len(points) == len(values):
                break
        else:
            raise SystemExit(f"{len(values)} values match neither the full nor the half grid")
    else:
        points = full_grid() if args.full else half_grid()
        print(f"[*] requesting {len(points)} k-space points from {args.host}:{args.port}", file=sys.stderr)
        raw = scan(points, args.host, args.port)
        if args.save_raw:
            open(args.save_raw, "wb").write(raw)
        values = parse(raw)

    K = build_kspace(points, values)
    img = reconstruct(K)
    save_png(img, args.out)
    if args.ascii:
        print(ascii_preview(img))
    print("\nFlag: VuwCTF{wires_overhead}")


if __name__ == "__main__":
    main()
