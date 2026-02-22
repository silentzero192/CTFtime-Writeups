from Crypto.Util.number import getPrime, inverse
import base64

def encode_length(l):
    if l < 128:
        return bytes([l])
    s = l.to_bytes((l.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(s)]) + s

def encode_integer(n):
    if n == 0:
        return b'\x02\x01\x00'
    s = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if s[0] & 0x80:
        s = b'\x00' + s
    return b'\x02' + encode_length(len(s)) + s

def encode_sequence(seq):
    return b'\x30' + encode_length(len(seq)) + seq

p = getPrime(512)
q = p

n = p * q
e = 65537
phi = (p - 1) * (q - 1)

d = inverse(e, phi)
dmp1 = d % (p - 1)
dmq1 = d % (p - 1)
iqmp = 0 # doesn't matter

seq = b''
seq += encode_integer(0) # version
seq += encode_integer(n)
seq += encode_integer(e)
seq += encode_integer(d)
seq += encode_integer(p)
seq += encode_integer(q)
seq += encode_integer(dmp1)
seq += encode_integer(dmq1)
seq += encode_integer(iqmp)

der = encode_sequence(seq)
pem = b'-----BEGIN RSA PRIVATE KEY-----\n' + base64.encodebytes(der) + b'-----END RSA PRIVATE KEY-----\n'

with open("key.pem", "wb") as f:
    f.write(pem)

print(pem.decode())
