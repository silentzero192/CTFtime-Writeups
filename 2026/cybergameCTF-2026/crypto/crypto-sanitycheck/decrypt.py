ct_hex = "30324f263735351656570a1b3a45573e1f56154a101641381605560d261b5507380959135026550d41380a5e1c1e"
ct = bytes.fromhex(ct_hex)
key = "cybergame"
pt = "".join(chr(ct[i] ^ ord(key[i % len(key)])) for i in range(len(ct)))
print(pt)
