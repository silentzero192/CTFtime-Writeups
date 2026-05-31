#!/usr/bin/env python3
import socket
import time

HOST = "10.42.99.10"
PORT = 1337
PROMPT = b"\n$ "

def recv_until_prompt(sock):
    data = b""
    while not data.endswith(PROMPT):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((HOST, PORT))
    banner = recv_until_prompt(sock).decode(errors="replace")
    print("[*] Got banner")

    for line in banner.split("\n"):
        if "iv" in line and ":" in line:
            IV_HEX = line.split(":")[1].strip()
        if "token" in line and ":" in line:
            TOKEN_HEX = line.split(":")[1].strip()

    print(f"[*] IV: {IV_HEX}")
    token_bytes = bytes.fromhex(TOKEN_HEX)
    blocks = [token_bytes[i:i+16] for i in range(0, len(token_bytes), 16)]
    print(f"[*] Blocks: {len(blocks)}")

    # For each block, recover intermediate using pipelined queries
    all_ct_blocks = [bytes.fromhex(IV_HEX)] + blocks

    for blk_idx, ct_block in enumerate(blocks):
        print(f"\n[*] Block {blk_idx+1}/{len(blocks)}")
        intermediate = bytearray(16)

        for byte_pos in range(15, -1, -1):
            pad_val = 16 - byte_pos
            
            cmds = []
            for guess in range(256):
                fake_iv = bytearray(16)
                for j in range(byte_pos + 1, 16):
                    fake_iv[j] = intermediate[j] ^ pad_val
                fake_iv[byte_pos] = guess
                cmds.append(f"DECRYPT {fake_iv.hex()} {ct_block.hex()}\n")

            all_cmd_data = "".join(cmds)
            sock.sendall(all_cmd_data.encode())

            # Read all 256 responses
            resp_data = b""
            while resp_data.count(PROMPT) < 256:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp_data += chunk

            responses = resp_data.split(PROMPT)
            ok_index = -1
            for i in range(256):
                if b"OK" in responses[i]:
                    ok_index = i
                    break

            if 0 <= ok_index < 256:
                intermediate[byte_pos] = ok_index ^ pad_val
                print(f"  Byte {byte_pos}: found (pad={pad_val}, guess={ok_index}) -> {intermediate[byte_pos]:02x}")
            else:
                print(f"  Byte {byte_pos}: NOT FOUND!")
                print(f"  Response debug: {resp_data[:200]}")

        # XOR intermediate with previous block to get plaintext
        prev = all_ct_blocks[blk_idx]
        pt_block = bytes(intermediate[i] ^ prev[i] for i in range(16))
        print(f"  Plaintext block: {pt_block}")

    # Re-read the final result
    sock.sendall(b"QUIT\n")
    sock.close()

if __name__ == "__main__":
    main()
