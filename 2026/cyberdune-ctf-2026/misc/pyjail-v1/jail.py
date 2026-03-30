#!/usr/bin/env python3
import sys
import warnings  # intentionally imported (useful for the intended escape path)

BANNER = r"""
   ____        __      ______      __
  / __ \__  __/ /___ _/ / __ \____/ /___
 / /_/ / / / / / __ `/ / / / / __  / __ \
/ ____/ /_/ / / /_/ / / /_/ / /_/ / /_/ /
/_/    \__, /_/\__,_/_/\__,_/\__,_/\____/
      /____/

Welcome to SafeCalc v1 (pyjail edition)
- arithmetic only
- dangerous words blocked
- 3 tries
"""

BLACKLIST = [
    "import",
    "open",
    "exec",
    "eval",
    "os",
    "system",
    "subprocess",
    "flag",
    "cat",
    "read",
]

MAX_LEN = 350

SAFE_GLOBALS = {"__builtins__": {}}
SAFE_LOCALS = {
    "pi": 3.1415926535,
    "e": 2.7182818284,
    "note": "safe mode",
}

def is_ascii_printable(s: str) -> bool:
    return all(32 <= ord(c) < 127 for c in s)

def check_payload(expr: str):
    if not expr:
        return "Empty input."
    if len(expr) > MAX_LEN:
        return f"Too long. Max {MAX_LEN} chars."
    if not is_ascii_printable(expr):
        return "ASCII printable only."
    low = expr.lower()
    for bad in BLACKLIST:
        if bad in low:
            return "Blocked keyword detected."
    return None

def main():
    print(BANNER, flush=True)

    tries = 3
    for _ in range(tries):
        sys.stdout.write(">>> ")
        sys.stdout.flush()

        line = sys.stdin.readline()
        if not line:
            return

        expr = line.rstrip("\r\n")

        if expr.lower() in {"exit", "quit"}:
            print("bye")
            return

        err = check_payload(expr)
        if err:
            print(err, flush=True)
            continue

        try:
            # intentionally vulnerable: naive blacklist + empty builtins
            result = eval(expr, SAFE_GLOBALS, SAFE_LOCALS)
            out = repr(result)
            if len(out) > 600:
                out = out[:600] + "...(truncated)"
            print(out, flush=True)
        except Exception as e:
            print(f"Error: {e.__class__.__name__}", flush=True)

    print("No more tries. Bye.", flush=True)

if __name__ == "__main__":
    main()
