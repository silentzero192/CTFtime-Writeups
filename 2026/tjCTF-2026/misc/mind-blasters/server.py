#!/usr/local/bin/python3
import pickle
import io
import socket
import threading
import base64
import re
import builtins
import abc


# This seems to be the main part of the chall... hmm
ALLOWED = {
    'type', 'getattr', 'len', 'range',
    'str', 'int', 'bytes', 'list', 'dict',
    'tuple', 'bool', 'set', 'frozenset', 'bytearray',
}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == 'builtins' and name in ALLOWED:
            return getattr(builtins, name)
        raise pickle.UnpicklingError('not allowed')


def safe_loads(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()


def handle_connection(conn):
    try:
        # filler text
        conn.sendall(b"=== Rick's Mind Blaster ===\n")
        conn.sendall(b"Maximum security. Nothing gets through.\n")
        conn.sendall(b"\nUpload a mind blaster (base64 encoded) > ")

        # i
        data = b''
        while b'\n' not in data:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        data = data.strip()

        if not data:
            return

        try:
            raw = base64.b64decode(data)
        except Exception:
            conn.sendall(b"thats not base64 bro\n")
            return

        # deserialize
        result = safe_loads(raw)
        result_str = str(result)
        ## strips flag patt
        result_str = re.sub(r'tjctf\{[^}]*\}', '[REDACTED]', result_str)
        conn.sendall(f"Result: {result_str}\n".encode())

    # error +closing
    except pickle.UnpicklingError:
        conn.sendall(b"blocked\n")
    except Exception as e:
        conn.sendall(f"error: {type(e).__name__}\n".encode())
    finally:
        conn.close()

# int main(int argc, char *argv[])
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 5000))
    server.listen(5)
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_connection, args=(conn,))
        t.daemon = True
        t.start()


if __name__ == '__main__':
    main()
