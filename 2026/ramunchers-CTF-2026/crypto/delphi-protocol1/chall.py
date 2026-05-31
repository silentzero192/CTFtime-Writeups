import os, socket, threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

SECRET_KEY = os.urandom(16)

try:
    with open("conversation.txt", "rb") as f:
        FLAG = f.read().strip()
except FileNotFoundError:
    FLAG = b"System: Error! conversation.txt not found. RAM{PLACEHOLDER_FLAG}"

IV = os.urandom(16)


def aes_cbc_encrypt(key, iv, pt):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(pt, 16))


def aes_cbc_decrypt_raw(key, iv, ct):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(ct)


def pkcs7_valid(data, bs=16):
    try:
        unpad(data, bs)
        return True
    except ValueError:
        return False


TOKEN = aes_cbc_encrypt(SECRET_KEY, IV, FLAG)

BANNER = f"""\
Delphi Backend Portal - Internal Log Access

Intercepted Transmission:
  token : {TOKEN.hex()}
  iv    : {IV.hex()}

Commands:
  DECRYPT iv_hex token_hex
  QUIT
"""

PROMPT = b"\n$ "


def decrypt_command(*args):
    if len(args) != 2:
        return b"ERROR: usage: DECRYPT iv_hex token"
    iv_hex, ct_hex = args
    try:
        iv_b = bytes.fromhex(iv_hex)
        ct_b = bytes.fromhex(ct_hex)
    except ValueError:
        return b"ERROR: invalid hex"

    pt = aes_cbc_decrypt_raw(SECRET_KEY, iv_b, ct_b)
    return b"OK" if pkcs7_valid(pt) else b"ERROR: malformed token"


def handle_client(conn):
    def respond(msg):
        conn.sendall((msg if isinstance(msg, bytes) else msg.encode()) + PROMPT)

    try:
        respond(BANNER)
        buf = ""
        while True:
            data = conn.recv(1024)
            if not data:
                break
            buf += data.decode(errors="replace")
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                parts = line.split()
                if not parts:
                    conn.sendall(PROMPT)
                    continue
                cmd, *args = parts
                if cmd.upper() == "QUIT":
                    conn.sendall(b"Goodbye.\n")
                    return
                elif cmd.upper() == "DECRYPT":
                    respond(decrypt_command(*args))
                else:
                    respond(b"ERROR: unknown command")
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


def main():
    port = 1337
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)
    print(f"Secure Token Validator listening on :{port}")
    print(f"Connect via nc")
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
