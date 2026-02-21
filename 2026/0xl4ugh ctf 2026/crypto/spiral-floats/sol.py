spiral_x = 21923564326773853297362998040140740534642596398113738053966234892634295369853

from Crypto.Util.number import bytes_to_long
from sage.all import RealField, sqrt


def spiral(x, phi, iterations=81):
    R = x.parent()
    for i in range(iterations):
        r = R(i) / R(iterations)
        x = r * sqrt(x * x + 1) + (1 - r) * (x + phi)
    return x

flag = bytes_to_long(b"0xL4ugh{?????????????????????}")

flen = len(str(flag))
R = RealField(256)
phi = R((1 + sqrt(5)) / 2)

x = R(flag) * R(10) ** (-flen)

x = str(spiral(x, phi)).replace(".", "")
