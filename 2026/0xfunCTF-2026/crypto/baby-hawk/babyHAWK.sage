# ==========================================
#  ██████╗ ██╗  ██╗███████╗██╗   ██╗███╗   ██╗
#  ██╔═████╗╚██╗██╔╝██╔════╝██║   ██║████╗  ██║
#  ██║██╔██║ ╚███╔╝ █████╗  ██║   ██║██╔██╗ ██║
#  ████╔╝██║ ██╔██╗ ██╔══╝  ██║   ██║██║╚██╗██║
#  ╚██████╔╝██╔╝ ██╗██║     ╚██████╔╝██║ ╚████║
#   ╚═════╝ ╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝
#
#                  Author:Hadi
#		  Challenge:babyHawk
# ==========================================
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from hashlib import sha256

from Crypto.Util.Padding import pad
from os import urandom
import random
import math

FLAG = open("flag.txt").read().strip().encode()


load("https://raw.githubusercontent.com/ludopulles/hawk-aux/refs/heads/main/code/hawk.sage")

d = 128
Sig = SignatureScheme(d, 2, sqrt(4), 4)

sk, pk = Sig.KGen()

f,g,F,G =  sk
B = matrix([[f,F],[g,G]])
S = B*B.H
Q = B.H*B


q0,q1,_,q2 = Q.coefficients()[:4]
s0,s1,_,s2 = S.coefficients()[:4]
assert q1.conjugate() == Q[1,0]


key = sha256(str(sk).encode()).digest()
iv = urandom(16)

cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
enc = cipher.encrypt(pad(FLAG, 16))

print("iv = "+'"'+ iv.hex()+'"')
print("enc ="+'"'+ enc.hex()+'"')

print(f"{q0,q1,q2 =}")
print(f"{s0,s1,s2 =}")