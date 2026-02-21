import base64, json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

password = "whoevenputsthepasswordhereandwhyisitsooooooLONG?"

with open("output.txt") as f:
    data = json.load(f)

salt = base64.b64decode(data["salt"])
nonce = base64.b64decode(data["nonce"])
ciphertext = base64.b64decode(data["ciphertext"])
tag = base64.b64decode(data["tag"])

key = PBKDF2(password.encode(), salt, dkLen=32, count=200000)

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)

print(plaintext.decode())
