from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import getrandbits
import hashlib
import os

flag = b'redacted'
key = os.urandom(len(flag)) 
Max_sample = 67 # :3

def get_safe_prime(bits):
    while True:
        q = getPrime(bits-1)
        p = 2*q + 1
        if isPrime(p):
            return p, q

def primitive_root(p, q):
    while True:
        g = getRandomRange(3, p-1)
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g 
    
def gen():
    p, q = get_safe_prime(42)   # Should've chosen a bigger prime, but got biased:3 [https://www.youtube.com/watch?v=aboZctrHfK8]
    g = primitive_root(p, q)
    h = pow(g, bytes_to_long(key), p)

    return g, h, p

Max_samples = Max_sample//8 # Can't give you that many samples:3
with open('output.txt', 'w') as f:
    for i in range(Max_samples):
        g, h, p = gen()
        f.write(f'sample #{i+1}:\n')
        f.write(f'{g = }\n')
        f.write(f'{h = }\n')
        f.write(f'{p = }\n')

    cipher = AES.new(hashlib.sha256(key).digest(), AES.MODE_ECB)
    ct = cipher.encrypt(pad(flag, 16)).hex()
    f.write(f'{ct = }')
