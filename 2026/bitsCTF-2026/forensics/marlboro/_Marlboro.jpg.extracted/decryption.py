from itertools import cycle

key_hex = "c7027f5fdeb20dc7308ad4a6999a8a3e069cb5c8111d56904641cd344593b657"
key = bytes.fromhex(key_hex)

with open("encrypted.bin", "rb") as f:
    data = f.read()

decrypted = bytes([b ^ k for b, k in zip(data, cycle(key))])

print(decrypted.decode(errors="ignore"))
