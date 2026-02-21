from randcrack import RandCrack
from pwn import *

rc = RandCrack()

conn = remote("chall.0xfun.org", 63201)

# for _ in range(5):
#     conn.sendline(b"spin")
#     conn.recv(2)
#     ouput = int(conn.recvline().strip())
#     print(ouput)
# output = int(conn.recvline().strip())
# raw = output ^ 0xCAFEBABE
# print(raw)

# collect 624 outputs
for _ in range(624):
    conn.sendline(b"spin")
    conn.recv(2)
    output = int(conn.recvline().strip())
    print(_)
    raw = output ^ 0xCAFEBABE
    rc.submit(raw)

# now predict next 10
conn.sendline(b"predict")

predictions = []
for _ in range(10):
    predictions.append(str(rc.predict_getrandbits(32)))

conn.sendline(" ".join(predictions).encode())

conn.interactive()
