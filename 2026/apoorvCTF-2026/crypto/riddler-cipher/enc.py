# enc.py

from Crypto.Util.number import *

e = 3

while True:
	p = getPrime(1024)
	q = getPrime(1024)
	N = p*q
	phi = (p-1)*(q-1)

	if GCD(phi, e) == 1:
		break

d = inverse(e, phi)

with open("flag.txt", "rb") as f:
	m = bytes_to_long(f.read())

assert m < N 

c = pow(m, e, N)

print("N = ", N)
print("e = ", e)
print("c = ", c)