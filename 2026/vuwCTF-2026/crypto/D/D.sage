import random, itertools, operator
key = random.Random(b"p-box").randbytes(128)

with open("flag.png", "rb") as f:
    flag = f.read()
    
p = len(flag)%16
if p!= 0:
    p = 16 - p
    flag+=bytes([p]*p)

F.<x> = GF(340282366920938463463374607431768211456)
R.<y> = PolynomialRing(F)

def D(n,a):
    if n == 0:
        return 0
    if n == 1:
        return y
    return y*D(n-1,a) - a*D(n-2, a)

p = D(13, F.from_integer(19))

@operator.call
def ks():
    while True:
        for i in range(8):
            l = F.from_bytes(key[i:i+16])
            for j in range(16):
                yield l.to_integer()
                l = p(l)

def encrypt_block(b):
    b = int.from_bytes(b)
    for i in range(16):
        b = p(F.from_integer(next(ks)^^b)).to_bytes()
        c = [0]*16
        for i in range(4):
            for j in range(4):
                c[j * 4 + i] = b[i + 4 * ((j + i) % 4)]
        b = int.from_bytes(bytes(c))

    return b.to_bytes(16)

s=bytes(16)
with open("flag.png.encrypted", "wb+") as f:
    for i in range(len(flag) // 16):
        s=encrypt_block(a^^b for a,b in zip(flag[i*16:i*16+16],s))
        f.write(s)
