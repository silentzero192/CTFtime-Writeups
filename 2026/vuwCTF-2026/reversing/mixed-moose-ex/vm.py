import struct, sys

dat = open("moose.dat","rb").read()
assert dat[:4] == b"MOOZ"
nprog = struct.unpack_from("<I", dat, 4)[0]
progs = []
for i in range(nprog):
    off, ln = struct.unpack_from("<II", dat, 8 + 8*i)
    progs.append(dat[off:off+ln])
    print(f"prog{i}: off=0x{off:x} len=0x{ln:x}")

M = 0xffffffff
def rotl(v,s):
    s &= 31
    return ((v << s) | (v >> ((32-s)&31))) & M if s else v & M
def rotr(v,s):
    s &= 31
    return ((v >> s) | (v << ((32-s)&31))) & M if s else v & M

OPS = {0x00:'HALT',0x01:'LOADI',0x02:'MOV',0x10:'XOR',0x11:'ADD',0x13:'MUL',
       0x14:'AND',0x15:'OR',0x16:'SHL',0x17:'SHR',0x1a:'XORSHR',0x23:'MULI',
       0x28:'ROTL',0x31:'JGE',0x40:'CALL'}

def disasm(code):
    pc = 0
    out = []
    while pc < len(code):
        st = pc
        op = code[pc]; pc += 1
        n = OPS.get(op, f'BAD{op:02x}')
        if op == 0x00: out.append((st,'HALT')); break
        elif op == 0x01:
            d = code[pc]; imm = struct.unpack_from("<I", code, pc+1)[0]; pc += 5
            out.append((st,f'LOADI r{d}, 0x{imm:08x}'))
        elif op in (0x02,0x10,0x11,0x13,0x14,0x15,0x16,0x17):
            d,s = code[pc],code[pc+1]; pc += 2
            out.append((st,f'{n} r{d}, r{s}'))
        elif op == 0x1a:
            d,i = code[pc],code[pc+1]; pc += 2
            out.append((st,f'XORSHR r{d} ^= r{d}>>{i}'))
        elif op == 0x23:
            d = code[pc]; imm = struct.unpack_from("<I", code, pc+1)[0]; pc += 5
            out.append((st,f'MULI r{d} *= 0x{imm:08x}'))
        elif op == 0x28:
            d,i = code[pc],code[pc+1]; pc += 2
            out.append((st,f'ROTL r{d} <<<= {i}'))
        elif op == 0x31:
            a,b = code[pc],code[pc+1]; rel = struct.unpack_from("<h", code, pc+2)[0]; pc += 4
            out.append((st,f'JGE r{a} >= r{b} -> pc+={rel} (=> 0x{pc+rel:x})'))
        elif op == 0x40:
            d,p,a,b,c = code[pc:pc+5]; pc += 5
            out.append((st,f'CALL r{d} = prog{p}(r{a}, r{b}, r{c})'))
        else:
            out.append((st,f'BAD 0x{op:02x}')); break
    return out

def run(pid, a0=0, a1=0, a2=0, a3=0):
    code = progs[pid]
    r = [0]*16
    r[0],r[1],r[2],r[3] = a0&M, a1&M, a2&M, a3&M
    pc = 0
    while pc < len(code):
        op = code[pc]; pc += 1
        if op == 0x00:
            return r[0]
        elif op == 0x01:
            d = code[pc]; imm = struct.unpack_from("<I", code, pc+1)[0]; pc += 5
            r[d] = imm
        elif op == 0x02:
            d,s = code[pc],code[pc+1]; pc += 2; r[d] = r[s]
        elif op == 0x10:
            d,s = code[pc],code[pc+1]; pc += 2; r[d] ^= r[s]
        elif op == 0x11:
            d,s = code[pc],code[pc+1]; pc += 2; r[d] = (r[d]+r[s]) & M
        elif op == 0x13:
            d,s = code[pc],code[pc+1]; pc += 2; r[d] = (r[d]*r[s]) & M
        elif op == 0x14:
            d,s = code[pc],code[pc+1]; pc += 2; r[d] &= r[s]
        elif op == 0x15:
            d,s = code[pc],code[pc+1]; pc += 2; r[d] |= r[s]
        elif op == 0x16:
            d,s = code[pc],code[pc+1]; pc += 2; r[d] = (r[d] << (r[s]&31)) & M
        elif op == 0x17:
            d,s = code[pc],code[pc+1]; pc += 2; r[d] = r[d] >> (r[s]&31)
        elif op == 0x1a:
            d,i = code[pc],code[pc+1]; pc += 2; r[d] ^= (r[d] >> (i&31))
        elif op == 0x23:
            d = code[pc]; imm = struct.unpack_from("<I", code, pc+1)[0]; pc += 5
            r[d] = (r[d]*imm) & M
        elif op == 0x28:
            d,i = code[pc],code[pc+1]; pc += 2; r[d] = rotl(r[d], i)
        elif op == 0x31:
            a,b = code[pc],code[pc+1]; rel = struct.unpack_from("<h", code, pc+2)[0]; pc += 4
            if r[a] >= r[b]: pc += rel
        elif op == 0x40:
            d,p,a,b,c = code[pc:pc+5]; pc += 5
            r[d] = run(p, r[a], r[b], r[c], 0)
        else:
            raise Exception(f"bad op {op:02x} pc={pc-1}")
    raise Exception("fell off end")

if __name__ == "__main__":
    for i,p in enumerate(progs):
        print(f"--- prog{i} ---")
        for st,t in disasm(p):
            print(f"  {st:3d}: {t}")
