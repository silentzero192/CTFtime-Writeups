#!/usr/bin/python3
import socket
import time

target1 = b"\x08?'!#!\x1b7"
part1 = ''.join(chr(target1[i] ^ ord("GibsonIs"[i])) for i in range(8))
print(f"part1 = {part1}")

def make_key(t):
    target2 = (int(t) >> 2).to_bytes(8, "little")
    part2 = ''.join(chr((b % 26) + 0x61) for b in target2)
    part3 = ''.join(chr(((ord(p1) + ord(p2)) % 26) + 0x61) for p1, p2 in zip(part1, part2))
    return ''.join(part1[i] + part3[i] + part2[i] for i in range(8))

start = int(time.time())
for offset in range(-4, 5):
    t = start + offset
    key = make_key(t)
    print(f"Trying offset={offset}, key={key}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect(("10.42.99.10", 1337))
        # Receive the prompt
        data = sock.recv(4096)
        print(f"  Prompt: {data}")
        # Send the key
        sock.sendall((key + "\n").encode())
        # Receive the response
        response = sock.recv(4096)
        print(f"  Response: {response}")
        if b"FLAG" in response or b"flag" in response or b"ram" in response or b"{" in response:
            print(f"*** FOUND FLAG: {response} ***")
            break
    except socket.timeout:
        print(f"  Timeout")
    except Exception as e:
        print(f"  Error: {e}")
    finally:
        sock.close()
