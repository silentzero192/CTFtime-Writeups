from Crypto.Util.number import bytes_to_long, getPrime

flag = "SK-CERT{************}"
m = bytes_to_long(flag.encode())
p = getPrime(192)
q = getPrime(192)
n = p*q
e = 65537
c = pow(m,e,n)
print("c: ", c)
print("n: ", n)
print("e: ", e)
