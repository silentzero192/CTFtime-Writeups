import hashlib
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes

d = 797362141196384868007066615792142575269512834174354422840008233995912822094171106431346799
k = long_to_bytes(d)

aes_key = hashlib.sha256(k + b"MeOwl::AES").digest()[:16]
des_key = hashlib.sha256(k + b"MeOwl::DES").digest()[:8]

ciphertext = bytes.fromhex(
    "7d34910bca6f505e638ed22f412dbf1b50d03243b739de0090d07fb097ec0a2c"
    "a19158949f32e39cd84adea33d2229556f635237088316d2"
)

des_iv = bytes.fromhex("86fd0c44751700d4")
aes_iv = bytes.fromhex("7d0e47bb8d111b626f0e17be5a761a14")

# first DES decrypt
c1 = DES.new(des_key, DES.MODE_CBC, iv=des_iv).decrypt(ciphertext)
c1 = unpad(c1, 8)

# then AES decrypt
flag = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv).decrypt(c1)
flag = unpad(flag, 16)

print(flag)
