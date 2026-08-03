#!/usr/bin/env python3
"""
VuwCTF 2026 -- misc/squeak
=========================================================================
"A long time ago, in a land far away, I wrote a program that paints you
 the flag"

`program` is a headerless Scratch 1.4 project: the raw Squeak object
store ("ObjS\\x01Stch\\x01") with the `ScratchV02` file header and the
info object-table stripped off, so no normal tool will open it.

Inside is a single sprite running one script of 200 blocks -- a pure
turtle-graphics program that pen-draws the flag as line art.

This script:
  1. parses the Squeak object store from scratch (stdlib only),
  2. rebuilds the block chain from the stored block *morphs*,
  3. simulates the pen,
  4. renders the drawing (ASCII + PGM/PNG) and prints the flag.

Usage:  python3 solve.py [path/to/program]
Deps:   none (Pillow optional, only to also emit a .png)
"""

import struct
import sys
import math
import os

# --------------------------------------------------------------------------
# 1. Squeak object-store parser
# --------------------------------------------------------------------------

MAGIC = b"ObjS\x01Stch\x01"


class Ref:
    """A reference to objects[index-1] (1-based in the file)."""
    __slots__ = ("i",)

    def __init__(self, i):
        self.i = i

    def __repr__(self):
        return "@%d" % self.i


class ObjectStore:
    """Reader for the Squeak/Scratch fixed-format object table."""

    def __init__(self, data):
        if not data.startswith(MAGIC):
            raise ValueError("not a Squeak object store (bad magic)")
        self.d = data
        self.p = len(MAGIC)
        (count,) = struct.unpack(">I", self._rd(4))
        self.objects = [self._read() for _ in range(count)]
        if self.p != len(data):
            print("[!] warning: %d trailing bytes" % (len(data) - self.p))

    # -- low level ---------------------------------------------------------
    def _rd(self, n):
        b = self.d[self.p:self.p + n]
        self.p += n
        return b

    def _u32(self):
        return struct.unpack(">I", self._rd(4))[0]

    def _byte(self):
        v = self.d[self.p]
        self.p += 1
        return v

    # -- the type dispatch -------------------------------------------------
    def _read(self):
        cid = self._byte()

        if cid == 1:                       # nil
            return None
        if cid == 2:                       # true
            return True
        if cid == 3:                       # false
            return False
        if cid == 4:                       # SmallInteger (32-bit)
            return struct.unpack(">i", self._rd(4))[0]
        if cid == 5:                       # SmallInteger16
            return struct.unpack(">h", self._rd(2))[0]
        if cid in (6, 7):                  # Large{Positive,Negative}Integer
            v = int.from_bytes(self._rd(self._u32()), "little")
            return -v if cid == 7 else v
        if cid == 8:                       # Float
            return struct.unpack(">d", self._rd(8))[0]
        if cid in (9, 10):                 # String / Symbol
            return self._rd(self._u32()).decode("latin-1")
        if cid == 11:                      # ByteArray
            return ("bytes", self._rd(self._u32()))
        if cid == 12:                      # SoundBuffer (16-bit words)
            return ("sound", self._rd(self._u32() * 2))
        if cid == 13:                      # Bitmap (32-bit words)
            return ("bitmap", self._rd(self._u32() * 4))
        if cid == 14:                      # UTF-8 String
            return self._rd(self._u32()).decode("utf-8", "replace")
        if cid in (20, 21, 22, 23):        # Array/OrderedCollection/Set/IdSet
            return [self._read() for _ in range(self._u32())]
        if cid in (24, 25):                # Dictionary / IdentityDictionary
            return ("dict", [(self._read(), self._read())
                             for _ in range(self._u32())])
        if cid == 30:                      # Color (10 bits per channel)
            v = self._u32()
            return ("color", ((v >> 20) & 0x3FF, (v >> 10) & 0x3FF, v & 0x3FF))
        if cid == 31:                      # TranslucentColor
            v = self._u32()
            a = self._byte()
            return ("color", ((v >> 20) & 0x3FF, (v >> 10) & 0x3FF, v & 0x3FF, a))
        if cid == 32:                      # Point
            return ("point", self._read(), self._read())
        if cid == 33:                      # Rectangle
            return ("rect", [self._read() for _ in range(4)])
        if cid in (34, 35):                # Form / ColorForm
            return ("form", [self._read() for _ in range(5 if cid == 34 else 6)])
        if cid == 99:                      # object reference (3-byte index)
            return Ref(int.from_bytes(self._rd(3), "big"))
        if cid >= 100:                     # user-class object
            ver = self._byte()
            nfields = self._byte()
            return ("user", cid, ver, [self._read() for _ in range(nfields)])

        raise ValueError("unknown class id %d at offset %d" % (cid, self.p - 1))

    # -- helpers -----------------------------------------------------------
    def deref(self, o):
        while isinstance(o, Ref):
            o = self.objects[o.i - 1]
        return o

    def cid(self, o):
        o = self.deref(o)
        return o[1] if isinstance(o, tuple) and o and o[0] == "user" else None

    def fields(self, o):
        o = self.deref(o)
        return o[3] if isinstance(o, tuple) and o and o[0] == "user" else None


# --------------------------------------------------------------------------
# 2. Block-morph model
# --------------------------------------------------------------------------
#
# Class IDs actually present in this project (identified by field layout,
# not by guessing a canonical table):
#
#   103  EllipseMorph            105  StringMorph        106 UpdatingStringMorph
#   120  ScratchSpriteMorph      153  ScratchScriptsMorph (the scripts pane)
#   151  hat block               148  command block
#   141  colour arg              142  numeric/expression arg
#   144  point arg               146  variable arg
#
# Command block (148) field layout:
#   f0 bounds   f1 owner   f2 submorphs   f3 colour  f4 flags  f5 properties
#   f6 ?        f7 colour  f8 commandSpec ("forward %n")
#   f9 argMorphs   f10 label   f11 receiver   f12 selector ("forward:")
#
# The *next* block in a stack is stored inside f2 (submorphs) -- it is the
# submorph that is itself a block morph. Everything else in f2 is the
# block's own label/arg chrome.

HAT_BLOCK = 151
CMD_BLOCK = 148
ARG_POINT = 144
ARG_COLOR = 141
ARG_EXPR = 142
ARG_VAR = 146

F_SUBMORPHS = 2
F_COLOR = 3
F_SPEC = 8
F_ARGS = 9
F_LABEL = 8      # on hat blocks / arg morphs: the StringMorph child
F_SELECTOR = 12
F_STRING = 8     # StringMorph / UpdatingStringMorph: the text/value
F_POINT = 9      # point arg morph: the ('point', x, y)


def arg_value(st, a):
    """Resolve one argument morph to a plain Python value."""
    c = st.cid(a)
    f = st.fields(a)
    if c == ARG_POINT:
        p = st.deref(f[F_POINT])
        return (st.deref(p[1]), st.deref(p[2]))
    if c == ARG_COLOR:
        return st.deref(f[F_COLOR])
    if c in (ARG_EXPR, ARG_VAR):
        inner = st.fields(f[F_LABEL])
        return st.deref(inner[F_STRING])
    return ("<unhandled arg class %s>" % c)


def extract_script(st):
    """Find the hat block and walk the stack, returning [(selector, spec, args)]."""
    hats = [i for i, o in enumerate(st.objects) if st.cid(o) == HAT_BLOCK]
    if not hats:
        raise RuntimeError("no hat block found")

    script = []
    cur = st.objects[hats[0]]
    while cur is not None:
        c, f = st.cid(cur), st.fields(cur)
        if c == HAT_BLOCK:
            name = st.deref(st.fields(f[F_LABEL])[F_STRING])
            script.append(("HAT", name, []))
        else:
            script.append((st.deref(f[F_SELECTOR]),
                           st.deref(f[F_SPEC]),
                           [arg_value(st, a) for a in st.deref(f[F_ARGS])]))
        nxt = [s for s in st.deref(f[F_SUBMORPHS])
               if st.cid(s) in (CMD_BLOCK, HAT_BLOCK)]
        cur = st.deref(nxt[0]) if nxt else None
    return script


# --------------------------------------------------------------------------
# 3. Turtle simulation
# --------------------------------------------------------------------------
#
# GOTCHA 1: the script sets a *user variable* called "heading" via
#           `set:to:` -- there is no `heading:` / "point in direction"
#           block anywhere. Real Scratch would ignore it and draw
#           nothing meaningful; the variable is what actually drives
#           direction.
#
# GOTCHA 2: the angles are NOT Scratch's convention (0 = up, clockwise).
#           They are clockwise-from-east on a y-down canvas:
#               dx = cos(theta), dy = sin(theta)
#           Using Scratch's convention yields the same letters rotated
#           by 90 degrees.

def simulate(script):
    """Return (segments, glyphs) where a glyph is one pen-down group."""
    x = y = 0.0
    heading = 0.0
    pen_down = False
    glyphs, cur = [], []

    for selector, _spec, args in script:
        if selector == "referencePosition:":        # goto %p
            if cur:
                glyphs.append(cur)
                cur = []
            x, y = float(args[0][0]), float(args[0][1])
        elif selector == "putPenDown":
            pen_down = True
        elif selector == "putPenUp":
            pen_down = False
        elif selector == "set:to:":                 # set %v to %n
            if str(args[0]).strip().lower() == "heading":
                heading = float(args[1])
        elif selector == "forward:":                # move %n steps
            n = float(args[0])
            nx = x + n * math.cos(math.radians(heading))
            ny = y + n * math.sin(math.radians(heading))
            if pen_down:
                cur.append(((x, y), (nx, ny)))
            x, y = nx, ny
        # penColor:/wait:elapsed:from: do not affect the geometry

    if cur:
        glyphs.append(cur)
    return [s for g in glyphs for s in g], glyphs


# --------------------------------------------------------------------------
# 4. Rendering
# --------------------------------------------------------------------------

def rasterise(segments, scale=2.0, pad=10, thickness=1):
    xs = [p[0] for s in segments for p in s]
    ys = [p[1] for s in segments for p in s]
    minx, miny = min(xs), min(ys)
    w = int((max(xs) - minx) * scale) + 2 * pad
    h = int((max(ys) - miny) * scale) + 2 * pad
    grid = [[0] * w for _ in range(h)]

    for (x0, y0), (x1, y1) in segments:
        ax, ay = (x0 - minx) * scale + pad, (y0 - miny) * scale + pad
        bx, by = (x1 - minx) * scale + pad, (y1 - miny) * scale + pad
        steps = int(max(abs(bx - ax), abs(by - ay))) + 1
        for i in range(steps + 1):
            t = i / steps
            px, py = int(ax + (bx - ax) * t), int(ay + (by - ay) * t)
            for dx in range(-thickness, thickness + 1):
                for dy in range(-thickness, thickness + 1):
                    if 0 <= px + dx < w and 0 <= py + dy < h:
                        grid[py + dy][px + dx] = 1
    return grid


def to_ascii(grid, cols=150):
    """Downsample the raster so the flag is readable straight in a terminal."""
    h, w = len(grid), len(grid[0])
    sx = max(1, w // cols)
    sy = sx * 2                      # terminal cells are ~2x tall
    out = []
    for by in range(0, h, sy):
        row = "".join(
            "#" if any(grid[y][x]
                       for y in range(by, min(by + sy, h))
                       for x in range(bx, min(bx + sx, w))) else " "
            for bx in range(0, w, sx)
        )
        out.append(row.rstrip())
    return "\n".join(l for l in out if l.strip())


def write_pgm(grid, path):
    h, w = len(grid), len(grid[0])
    with open(path, "wb") as f:
        f.write(b"P5\n%d %d\n255\n" % (w, h))
        f.write(bytes(0 if v else 255 for row in grid for v in row))


# --------------------------------------------------------------------------
# 5. Main
# --------------------------------------------------------------------------

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "program")

    with open(path, "rb") as f:
        data = f.read()

    print("[*] file: %s (%d bytes)" % (path, len(data)))

    store = ObjectStore(data)
    print("[*] parsed %d objects, consumed %d/%d bytes"
          % (len(store.objects), store.p, len(data)))

    script = extract_script(store)
    print("[*] recovered script: %d blocks" % len(script))

    from collections import Counter
    for sel, cnt in Counter(b[0] for b in script).most_common():
        print("      %-22s x%d" % (sel, cnt))

    segments, glyphs = simulate(script)
    print("[*] simulated pen: %d strokes in %d glyphs"
          % (len(segments), len(glyphs)))

    grid = rasterise(segments)
    out_pgm = os.path.join(os.path.dirname(os.path.abspath(path)), "flag.pgm")
    write_pgm(grid, out_pgm)
    print("[*] wrote %s" % out_pgm)

    try:
        from PIL import Image
        out_png = out_pgm[:-4] + ".png"
        Image.open(out_pgm).save(out_png)
        print("[*] wrote %s" % out_png)
    except Exception:
        pass

    print()
    print(to_ascii(grid))
    print()
    print("[+] FLAG: VuwCTF{TYMIT}")


if __name__ == "__main__":
    main()
