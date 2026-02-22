#!/usr/bin/env python3
import ast
import re
import socket
import sys
import time

HOST = "chal.bearcatctf.io"
PORT = 45457
PROMPT = b"Where is the battleship > "
FLAG_RE = re.compile(rb"BCCTF\{[^}\r\n]*\}")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def load_round_configs(path="battleship.py"):
    with open(path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=path)

    tuples = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            for stmt in node.body:
                if (
                    isinstance(stmt, ast.Assign)
                    and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)
                ):
                    name = stmt.targets[0].id
                    if name in {"easy", "medium", "hard"}:
                        tuples[name] = ast.literal_eval(stmt.value)
            break

    configs = {}
    for name in ("easy", "medium", "hard"):
        size, attempts, basis = tuples[name]
        pos = {int(v): (idx // size, idx % size) for idx, v in enumerate(basis)}
        configs[name] = {
            "size": size,
            "attempts": attempts,
            "value_to_pos": pos,
            "zero_orig": pos[0],
        }
    return configs


class Conn:
    def __init__(self, host, port, timeout=10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = bytearray()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def sendline(self, line):
        self.sock.sendall(line.encode() + b"\n")

    def recv_until(self, markers, timeout=8.0):
        end = time.monotonic() + timeout
        markers = tuple(markers)

        while time.monotonic() < end:
            for m in markers:
                if m in self.buf:
                    data = bytes(self.buf)
                    self.buf.clear()
                    return data, False

            if FLAG_RE.search(self.buf):
                data = bytes(self.buf)
                self.buf.clear()
                return data, False

            remaining = end - time.monotonic()
            self.sock.settimeout(min(1.0, max(0.05, remaining)))
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue

            if not chunk:
                data = bytes(self.buf)
                self.buf.clear()
                return data, True

            self.buf.extend(chunk)

        data = bytes(self.buf)
        self.buf.clear()
        return data, False


def parse_revealed_value(screen_bytes, size, row, col):
    text = ANSI_RE.sub("", screen_bytes.decode("utf-8", "ignore"))
    idx = text.rfind("Attempts left:")
    if idx == -1:
        raise ValueError("No board found in server output")

    lines = text[idx:].splitlines()
    board_lines = lines[1 : 1 + size]
    if len(board_lines) < size:
        raise ValueError("Incomplete board in server output")

    token = board_lines[row].split()[col]
    if token.startswith("X"):
        raise ValueError(f"Cell ({row}, {col}) is still masked")
    return int(token)


def solve_one_round(conn, cfg, is_last_round=False):
    n = cfg["size"]
    value_to_pos = cfg["value_to_pos"]
    zero_i, zero_j = cfg["zero_orig"]

    row_target = None
    col_target = None

    seen_rows = set()
    seen_cols = set()

    for k in range(n - 1):
        conn.sendline(f"{k} {k}")
        out, closed = conn.recv_until(
            (
                PROMPT,
                b"Try again",
                b"Sorry skipper",
                b"You are truly the greatest admiral we have seen",
            ),
            timeout=28.0 if n == 30 else 12.0,
        )
        if closed:
            return out
        if not out:
            raise TimeoutError("No output received after guess")
        if b"Try again" in out or b"Sorry skipper" in out:
            raise RuntimeError("Challenge failed mid-round")
        if b"Yay you won!" in out or b"You are truly the greatest admiral we have seen" in out:
            return out

        val = parse_revealed_value(out, n, k, k)
        orig_i, orig_j = value_to_pos[val]
        seen_rows.add(k)
        seen_cols.add(k)

        if orig_i == zero_i:
            row_target = k
        if orig_j == zero_j:
            col_target = k

        if row_target is None and len(seen_rows) == n - 1:
            row_target = (set(range(n)) - seen_rows).pop()
        if col_target is None and len(seen_cols) == n - 1:
            col_target = (set(range(n)) - seen_cols).pop()

        if row_target is not None and col_target is not None:
            conn.sendline(f"{row_target} {col_target}")
            finish_out, _ = conn.recv_until(
                (
                    PROMPT,
                    b"Try again",
                    b"Sorry skipper",
                    b"You are truly the greatest admiral we have seen",
                ),
                timeout=30.0 if n == 30 else 14.0,
            )
            if not finish_out:
                raise TimeoutError("No output received after final guess")
            return finish_out

    if row_target is None:
        row_target = (set(range(n)) - seen_rows).pop()
    if col_target is None:
        col_target = (set(range(n)) - seen_cols).pop()

    conn.sendline(f"{row_target} {col_target}")
    finish_out, _ = conn.recv_until(
        (
            PROMPT,
            b"Try again",
            b"Sorry skipper",
            b"You are truly the greatest admiral we have seen",
        ),
        timeout=30.0 if n == 30 else 14.0,
    )
    if not finish_out:
        raise TimeoutError("No output received after final guess")
    return finish_out


def extract_flag(blob):
    m = FLAG_RE.search(blob)
    return m.group(0).decode() if m else None


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    cfgs = load_round_configs("battleship.py")
    rounds = ["easy"] * 10 + ["medium"] * 10 + ["hard"] * 10
    all_output = bytearray()

    conn = Conn(host, port)
    try:
        menu, _ = conn.recv_until((b"5. Exit",), timeout=6.0)
        all_output.extend(menu)
        conn.sendline("4")

        opening, _ = conn.recv_until((PROMPT,), timeout=8.0)
        all_output.extend(opening)

        for idx, name in enumerate(rounds, start=1):
            print(f"round {idx}/30: {name}", flush=True)
            out = solve_one_round(conn, cfgs[name], is_last_round=(idx == 30))
            all_output.extend(out)
            if b"Try again" in out or b"Sorry skipper" in out:
                raise RuntimeError(f"Challenge failed on round {idx}")

        tail, _ = conn.recv_until((b"}",), timeout=3.0)
        all_output.extend(tail)
    finally:
        conn.close()

    flag = extract_flag(bytes(all_output))
    if not flag:
        raise RuntimeError("Flag not found in server output")
    print(f"FLAG {flag}")


if __name__ == "__main__":
    main()
