import re

with open("msg.enc") as f:
    ciphertext = f.read()

dec = []
for i, c in enumerate(ciphertext):
    if c.isalpha():
        base = ord('A') if c.isupper() else ord('a')
        dec.append(chr((ord(c) - base - (i + 1)) % 26 + base))
    else:
        dec.append(c)

plaintext = ''.join(dec)
print(plaintext)

match = re.search(r'RMCTF\{[^}]+\}', plaintext, re.IGNORECASE)
if match:
    print(f"\nFlag: {match.group().upper()}")

dept_match = re.search(r'department\s+(\S+)', plaintext)
if dept_match:
    print(f"Flag: RMCTF{{{dept_match.group(1)}}}")
