import base64
import math
import re
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import inverse


def parse_output(path):
    text = Path(path).read_text()

    def get(name):
        match = re.search(rf"^{name}\s*=\s*(.+)$", text, re.M)
        if not match:
            raise ValueError(f"Missing field: {name}")
        return match.group(1)

    return {
        "n": int(get("n"), 0),
        "e": int(get("e"), 0),
        "ct": base64.b64decode(get("ct")),
        "iv": base64.b64decode(get("iv")),
        "flag_ct": base64.b64decode(get("flag_ct")),
    }


def main():
    data = parse_output(Path(__file__).with_name("output.txt"))

    n = data["n"]
    p = math.isqrt(n)
    if p * p != n:
        raise ValueError("Expected a square modulus.")

    lam = p * (p - 1)
    d = inverse(data["e"], lam)
    key = pow(int.from_bytes(data["ct"], "big"), d, n).to_bytes(16, "big")

    cipher = AES.new(key, AES.MODE_CBC, data["iv"])
    flag = unpad(cipher.decrypt(data["flag_ct"]), 16).decode()
    print(flag)


if __name__ == "__main__":
    main()
