#!/usr/bin/env python3
"""copland-opportunity — full solve.

HFS+ volume with every folder record deleted from the catalog B-tree (so TSK cannot
traverse it). Recovers the file records by hand, extracts 87 single-character PNGs,
then recovers their arrangement from the .DS_Store Iloc (Finder icon location) records.
"""
import struct
from PIL import Image

IMG = 'disk-folders-removed.img'
d   = open(IMG, 'rb').read()

# ---------------------------------------------------------------- volume header
vh = d[1024:1024+512]
assert vh[:2] == b'H+'
BS, TOTAL_BLOCKS, FREE_BLOCKS = struct.unpack_from('>III', vh, 40)

def fork(buf, o):
    """HFSPlusForkData -> (logicalSize, [(startBlock, blockCount), ...])"""
    logical, _clump, _tot = struct.unpack_from('>QII', buf, o)
    ext = [struct.unpack_from('>II', buf, o + 16 + i*8) for i in range(8)]
    return logical, [e for e in ext if e[1]]

_, CATALOG_EXT = fork(vh, 112 + 80*2)          # allocation, extents, [catalog]

# ---------------------------------------------------------------- catalog B-tree
cat = b''.join(d[s*BS:(s+c)*BS] for s, c in CATALOG_EXT)
NS  = struct.unpack_from('>H', cat, 14 + 18)[0]          # BTHeaderRec.nodeSize

files = {}                                                # name -> (size, extents)
for n in range(len(cat) // NS):
    node = cat[n*NS:(n+1)*NS]
    _fl, _bl, kind, _h, numRecs, _r = struct.unpack_from('>IIbbHH', node, 0)
    if kind != -1 or not 0 < numRecs < 1000:              # -1 == kBTLeafNode
        continue
    offs = [struct.unpack_from('>H', node, NS - 2*(i+1))[0] for i in range(numRecs+1)]
    for i in range(numRecs):
        rec = node[offs[i]:offs[i+1]]
        if len(rec) < 10:
            continue
        keyLen  = struct.unpack_from('>H', rec, 0)[0]
        nameLen = struct.unpack_from('>H', rec, 6)[0]
        name    = rec[8:8+nameLen*2].decode('utf-16-be', 'replace')
        ro = 2 + keyLen
        ro += ro % 2
        if ro + 2 > len(rec) or struct.unpack_from('>h', rec, ro)[0] != 2:
            continue                                      # 2 == kHFSPlusFileRecord
        files[name] = fork(rec, ro + 88)                  # data fork

def read(name):
    size, ext = files[name]
    return b''.join(d[s*BS:(s+c)*BS] for s, c in ext)[:size]

# ---------------------------------------------------------------- .DS_Store (Bud1)
def ds_records(buf):
    assert buf[4:8] == b'Bud1'
    aoff, _asize, _copy = struct.unpack_from('>III', buf, 8)
    a = aoff + 4
    nblocks = struct.unpack_from('>I', buf, a)[0]
    addrs   = [struct.unpack_from('>I', buf, a + 8 + 4*i)[0] for i in range(nblocks)]
    p = a + 8 + 4*256                                     # skip the 256-slot offset table
    ndir = struct.unpack_from('>I', buf, p)[0]; p += 4
    dirs = {}
    for _ in range(ndir):
        nl = buf[p]; p += 1
        key = buf[p:p+nl].decode(); p += nl
        dirs[key] = struct.unpack_from('>I', buf, p)[0]; p += 4

    def block(bid):
        v = addrs[bid]
        return (v & ~0x1f) + 4                            # low 5 bits encode log2(size)

    out = []

    def record(p):
        nl = struct.unpack_from('>I', buf, p)[0]; p += 4
        name = buf[p:p+nl*2].decode('utf-16-be'); p += nl*2
        sid  = buf[p:p+4].decode('latin1'); p += 4
        typ  = buf[p:p+4].decode('latin1'); p += 4
        if   typ == 'bool':            val = buf[p]; p += 1
        elif typ in ('long', 'shor'):  val = struct.unpack_from('>I', buf, p)[0]; p += 4
        elif typ in ('comp', 'dutc'):  val = struct.unpack_from('>Q', buf, p)[0]; p += 8
        elif typ == 'type':            val = buf[p:p+4]; p += 4
        elif typ == 'blob':
            n = struct.unpack_from('>I', buf, p)[0]; p += 4
            val = buf[p:p+n]; p += n
        elif typ == 'ustr':
            n = struct.unpack_from('>I', buf, p)[0]; p += 4
            val = buf[p:p+n*2].decode('utf-16-be'); p += n*2
        else:
            raise ValueError('unknown .DS_Store type ' + typ)
        return p, (name, sid, typ, val)

    def node(bid):
        o = block(bid)
        P, count = struct.unpack_from('>II', buf, o)
        p = o + 8
        if P == 0:                                        # leaf
            for _ in range(count):
                p, r = record(p); out.append(r)
        else:                                             # internal: child, rec, child, ...
            for _ in range(count):
                child = struct.unpack_from('>I', buf, p)[0]; p += 4
                node(child)
                p, r = record(p); out.append(r)
            node(P)

    root, _levels, _nrec, _nnodes, _pagesize = struct.unpack_from('>IIIII', buf, block(dirs['DSDB']))
    node(root)
    return out

ilocs = []
for name, sid, typ, val in ds_records(read('.DS_Store')):
    if sid == 'Iloc' and typ == 'blob':
        x, y = struct.unpack_from('>II', val, 0)
        ilocs.append((name, x, y))
assert len(ilocs) == 87

# ---------------------------------------------------------------- recompose
import io
glyph = {n: Image.open(io.BytesIO(read(n))).convert('RGBA') for n, _, _ in ilocs}

W = max(x for _, x, _ in ilocs) + 200
H = max(y for _, _, y in ilocs) + 200
canvas = Image.new('RGB', (W, H), 'white')
for n, x, y in ilocs:
    canvas.paste(glyph[n], (x, y), glyph[n])
canvas.save('canvas_full.png')

# ---------------------------------------------------------------- isolate the message
# The flag row is the tight y-band 430..475; the two decoys that share it sit outside
# the message's horizontal extent (x < 380 and x > 2200).
row = sorted((r for r in ilocs if 430 <= r[2] <= 475 and 380 <= r[1] <= 2200),
             key=lambda r: r[1])
assert len(row) == 25

x0 = min(x for _, x, _ in row)
y0 = min(y for _, _, y in row)
strip = Image.new('RGB', (max(x for _, x, _ in row) - x0 + 150, 125), 'white')
for n, x, y in row:
    strip.paste(glyph[n], (x - x0, y - y0), glyph[n])
strip.save('flag_row.png')

print('wrote canvas_full.png and flag_row.png')
print('flag_row.png reads: VUWcTf{N0T_a_raNS0M_NOTe}')
print('glyph case is randomised per character by the generator -> normalise it:')
print('FLAG: VuwCTF{N0T_a_raNS0M_NOTe}')

