#!/usr/bin/env python3
import re
import socket
import sys


HOST = "34.126.223.46"
PORT = 17711


def main() -> int:
    with socket.create_connection((HOST, PORT)) as sock:
        sock.settimeout(5)
        data = ""
        game_data = ""
        handled = 0
        started = False

        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break

            text = chunk.decode("utf-8", errors="replace")
            sys.stdout.write(text)
            sys.stdout.flush()
            data += text

            if not started and "*********************************************" in data:
                started = True
                game_data = data.split("*********************************************", 1)[1]
            elif started:
                game_data += text

            if not started:
                continue

            matches = list(re.finditer(r"I GIVE:\s*(\d+)", game_data))
            while handled < len(matches):
                value = int(matches[handled].group(1)) + 10
                sock.sendall(f"{value}\n".encode())
                handled += 1

            if "kashiCTF{" in data:
                break

    return 0


if __name__ == "__main__":
    sys.exit(main())
