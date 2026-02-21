import re

# ─────────────────────────────────────────────
# STEP 0: Read the .sub file
# ─────────────────────────────────────────────
with open('Tesla.sub', 'rb') as f:
    content = f.read()

text = content.decode('latin-1')

raw_line = ''
for line in text.split('\n'):
    if line.startswith('RAW_Data:'):
        raw_line = line.replace('RAW_Data:', '').strip()
        break

print("[*] Found RAW_Data field")

# ─────────────────────────────────────────────
# STEP 1: Binary -> ASCII
# The RAW_Data contains space-separated 8-bit binary values.
# Skip the first 2 bytes (FF FE = UTF-16 LE BOM).
# ─────────────────────────────────────────────
binary_groups = raw_line.split()
raw_bytes = bytes(int(b, 2) for b in binary_groups)
script = raw_bytes[2:].decode('utf-8', errors='replace')   # skip BOM

print("[*] Decoded binary -> script text")

# ─────────────────────────────────────────────
# STEP 2: Deobfuscate CMD %var:~N,1% substitution
# The script sets a variable with a scrambled alphabet,
# then constructs commands by indexing into it.
# ─────────────────────────────────────────────
lookup = "pesbMUQl73oWnqD9rAvFRKZaf0hO5@dBN4uSzCtGjE YxITwXiVm1Jcgy26LkH8P"

all_indices = re.findall(r':~(\d+),1%', script)
decoded_cmd = ''.join(lookup[int(i)] for i in all_indices if int(i) < len(lookup))

print("[*] Deobfuscated CMD script:")
print("    " + decoded_cmd)

# ─────────────────────────────────────────────
# STEP 3: Extract the XOR ciphertext
# The PowerShell command embeds the ciphertext in a CMD comment (:: line).
# The comment line's indexed chars decode to the hex string.
# ─────────────────────────────────────────────
# Line 2 (the :: comment) indices decode to the ciphertext hex:
comment_line_indices = [
    '42','28','15','28','62','25','28','52','23','52','3','52','8','25','25',
    '52','9','28','57','25','8','33','58','57','58','28','23','25','1','28',
    '52','33','9','28','3','9','58','52','58','28','8','28','57','33','8',
    '25','3','8','24','25','9','28','15','52','30','52','3','9','58','33',
    '3','28','25','52','58','25','62','58','52','58','1','42'
]
ciphertext_hex = ''.join(lookup[int(i)] for i in comment_line_indices).strip()
print(f"\n[*] Extracted ciphertext (hex): {ciphertext_hex}")

# ─────────────────────────────────────────────
# STEP 4: XOR decrypt
# The XOR key is "i could be something to this" —
# extracted from the first part of the PowerShell GetBytes() argument.
# ─────────────────────────────────────────────
xor_key = "i could be something to this"
cipher_bytes = bytes.fromhex(ciphertext_hex)
plaintext = bytes(
    cipher_bytes[i] ^ ord(xor_key[i % len(xor_key)])
    for i in range(len(cipher_bytes))
)

flag = plaintext.decode('utf-8', errors='replace').rstrip('\r\n')
print(f"\n[+] FLAG: {flag}")
