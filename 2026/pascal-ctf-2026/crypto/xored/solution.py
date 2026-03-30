import random


def xor(a, b):
    return a ^ b


# given output
hex_cipher = "cb35d9a7d9f18b3cfc4ce8b852edfaa2e83dcd4fb44a35909ff3395a2656e1756f3b505bf53b949335ceec1b70e0"
cipher = bytes.fromhex(hex_cipher)

random.seed(1337)

flag = b""
for c in cipher:
    key = random.randint(0, 255)
    flag += bytes([xor(c, key)])

print(flag.decode())
