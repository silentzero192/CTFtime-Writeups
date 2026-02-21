from base64 import b16decode, b32decode, b64decode, b85decode
from hashlib import sha1

SCHEMES = [
    ("b16", b16decode),
    ("b32", b32decode),
    ("b64", b64decode),
    ("b85", b85decode),
]

with open("output", "rb") as f:
    current = f.read()

for round in range(16):
    checksum = current[-20:]
    encoded  = current[:-20]

    for name, decoder in SCHEMES:
        try:
            decoded = decoder(encoded)
            if sha1(decoded).digest() == checksum:
                print(f"[+] Round {16-round} used {name}")
                current = decoded
                break
        except:
            continue
    else:
        print("[-] No valid scheme found!")
        break

print("FLAG:", current.decode())
