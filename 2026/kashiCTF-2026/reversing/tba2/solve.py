#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


HOOK_SOURCE = r"""
#define _GNU_SOURCE

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef EXPECTED_LEN
#define EXPECTED_LEN 74
#endif

static int (*real_memcmp)(const void *, const void *, size_t);

static void write_hex_line(const unsigned char *buf, size_t len) {
    static const char hex[] = "0123456789abcdef";
    char out[2];

    write(STDERR_FILENO, "TBA2_FLAG_HEX:", 14);
    for (size_t i = 0; i < len; i++) {
        out[0] = hex[buf[i] >> 4];
        out[1] = hex[buf[i] & 0x0f];
        write(STDERR_FILENO, out, 2);
    }
    write(STDERR_FILENO, "\n", 1);
}

int memcmp(const void *lhs, const void *rhs, size_t len) {
    (void)lhs;

    if (!real_memcmp) {
        real_memcmp = dlsym(RTLD_NEXT, "memcmp");
    }

    if (len == EXPECTED_LEN) {
        write_hex_line((const unsigned char *)rhs, len);
    }

    return real_memcmp(lhs, rhs, len);
}
"""


def run_command(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=False,
        text=True,
        capture_output=True,
        **kwargs,
    )


def build_hook(tmpdir: Path, expected_len: int) -> Path:
    gcc = shutil.which("gcc")
    if not gcc:
        raise RuntimeError("gcc is required to build the LD_PRELOAD hook")

    hook_source = tmpdir / "memcmp_hook.c"
    hook_so = tmpdir / "memcmp_hook.so"
    hook_source.write_text(HOOK_SOURCE, encoding="ascii")

    compile_cmd = [
        gcc,
        "-shared",
        "-fPIC",
        "-O2",
        "-Wall",
        "-Wextra",
        f"-DEXPECTED_LEN={expected_len}",
        str(hook_source),
        "-o",
        str(hook_so),
        "-ldl",
    ]

    result = run_command(compile_cmd)
    if result.returncode != 0:
        raise RuntimeError(
            "failed to compile hook:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    return hook_so


def extract_flag(binary: Path, expected_len: int) -> tuple[str, subprocess.CompletedProcess[str]]:
    dummy_candidate = "A" * expected_len

    with tempfile.TemporaryDirectory(prefix="tba2-solve-") as tmp:
        tmpdir = Path(tmp)
        hook_so = build_hook(tmpdir, expected_len)

        env = os.environ.copy()
        env["LD_PRELOAD"] = str(hook_so)

        result = run_command(
            [str(binary), dummy_candidate],
            cwd=binary.parent,
            env=env,
        )

    matches = re.findall(r"TBA2_FLAG_HEX:([0-9a-f]+)", result.stderr)
    if not matches:
        raise RuntimeError(
            "flag buffer was not captured from memcmp\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    flag_bytes = bytes.fromhex(matches[-1])
    return flag_bytes.decode("ascii"), result


def verify_flag(binary: Path, flag: str) -> subprocess.CompletedProcess[str]:
    return run_command([str(binary), flag], cwd=binary.parent)


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="Recover the real flag from the tba2 challenge binary.",
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=script_dir / "prog",
        help="path to the challenge executable (default: ./prog)",
    )
    parser.add_argument(
        "--length",
        type=int,
        default=0x4A,
        help="expected flag length used by the final memcmp (default: 74)",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="skip the final verification run",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    binary = args.binary.resolve()

    if not binary.is_file():
        print(f"[-] binary not found: {binary}", file=sys.stderr)
        return 1

    print(f"[*] Using binary: {binary}")
    print("[*] Building preload hook and extracting the real comparison buffer...")

    try:
        flag, first_run = extract_flag(binary, args.length)
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    print(f"[+] Recovered flag: {flag}")

    if not args.no_verify:
        print("[*] Verifying the recovered flag against the original binary...")
        verify = verify_flag(binary, flag)
        sys.stdout.write(verify.stdout)
        if verify.returncode != 0:
            sys.stderr.write(verify.stderr)
            print("[-] verification failed", file=sys.stderr)
            return 1
        print("[+] Verification succeeded.")
    else:
        if first_run.stdout:
            sys.stdout.write(first_run.stdout)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
