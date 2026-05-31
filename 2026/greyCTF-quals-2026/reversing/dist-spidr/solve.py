#!/usr/bin/env python3
"""
Solve script for GreyCTF Quals 2026 - spidr

The binary reads one unsigned 64-bit integer, runs it through a long chain of
arithmetic/XOR transforms, and checks whether the final value matches a fixed
target. Every transformation is invertible modulo 2^64, so we can recover the
required input exactly by parsing the disassembly and walking the chain in
reverse.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from typing import Dict, List, Tuple

MOD = 1 << 64


def run_objdump(binary: str) -> str:
    return subprocess.check_output(
        ["objdump", "-d", "-Mintel", binary],
        text=True,
    )


def parse_functions(disassembly: str) -> Dict[str, str]:
    func_re = re.compile(
        r"^([0-9a-f]+) <([^>]+)>:\n(.*?)(?=\n^[0-9a-f]+ <|\Z)",
        re.S | re.M,
    )
    return {name: body for _, name, body in func_re.findall(disassembly)}


def parse_main(main_body: str) -> Tuple[str, int]:
    call_match = re.search(r"call\s+[0-9a-fx]+ <(_Z[^>]+)>", main_body)
    if not call_match:
        raise RuntimeError("Could not find the entry transform called from main")

    target_match = re.search(
        r"movabs rax,0x([0-9a-f]+)\n.*?cmp\s+rdx,rax",
        main_body,
        re.S,
    )
    if not target_match:
        raise RuntimeError("Could not find the final comparison target in main")

    return call_match.group(1), int(target_match.group(1), 16)


def parse_transform_function(body: str) -> Tuple[int, Dict[int, Tuple[str, ...]]]:
    init_match = re.search(r"mov\s+DWORD PTR \[rbp-0x4\],0x([0-9a-f]+)", body)
    if not init_match:
        raise RuntimeError("Could not find function state initialization")
    initial_state = int(init_match.group(1), 16)

    state_re = re.compile(
        r"cmp\s+DWORD PTR \[rbp-0x4\],0x([0-9a-f]+)(.*?)(?=cmp\s+DWORD PTR \[rbp-0x4\],0x|$)",
        re.S,
    )

    states: Dict[int, Tuple[str, ...]] = {}
    for state_hex, block in state_re.findall(body):
        state = int(state_hex, 16)

        call_match = re.search(r"call\s+[0-9a-fx]+ <([^>]+)>", block)
        if call_match:
            states[state] = ("call", call_match.group(1))
            continue

        next_state_match = re.search(
            r"mov\s+DWORD PTR \[rbp-0x4\],0x([0-9a-f]+)",
            block,
        )
        constant_match = re.search(r"movabs rdx,0x([0-9a-f]+)", block)
        if next_state_match and constant_match:
            next_state = int(next_state_match.group(1), 16)
            constant = int(constant_match.group(1), 16)

            if "imul   rdx,rax" in block:
                op = "mul"
            elif "xor    rdx,rax" in block:
                op = "xor"
            elif "add    rdx,rax" in block:
                op = "add"
            else:
                raise RuntimeError(f"Unknown operation in state {state_hex}")

            states[state] = (op, str(constant), str(next_state))
            continue

        # The final function terminates with a bare `je end` case instead of a
        # normal arithmetic block. Reaching it means the whole chain is done.
        states[state] = ("ret",)

    return initial_state, states


def flatten_operations(functions: Dict[str, str], entry_func: str) -> List[Tuple[str, int]]:
    operations: List[Tuple[str, int]] = []
    current_func = entry_func
    seen_funcs = set()

    while current_func is not None:
        if current_func in seen_funcs:
            raise RuntimeError(f"Detected a cycle in the function chain at {current_func}")
        seen_funcs.add(current_func)

        initial_state, states = parse_transform_function(functions[current_func])
        current_state = initial_state
        seen_states = set()

        while True:
            if current_state in seen_states:
                raise RuntimeError(
                    f"Detected a cycle inside {current_func} at state {hex(current_state)}"
                )
            seen_states.add(current_state)

            action = states[current_state]
            kind = action[0]

            if kind == "call":
                current_func = action[1]
                break
            if kind == "ret":
                current_func = None
                break

            op = kind
            constant = int(action[1])
            next_state = int(action[2])
            operations.append((op, constant))
            current_state = next_state

    return operations


def invert_operations(operations: List[Tuple[str, int]], target: int) -> int:
    value = target
    for op, constant in reversed(operations):
        if op == "add":
            value = (value - constant) % MOD
        elif op == "xor":
            value ^= constant
        elif op == "mul":
            value = (value * pow(constant, -1, MOD)) % MOD
        else:
            raise RuntimeError(f"Unsupported operation {op}")
    return value


def verify_forward(operations: List[Tuple[str, int]], start: int, target: int) -> bool:
    value = start
    for op, constant in operations:
        if op == "add":
            value = (constant + value) % MOD
        elif op == "xor":
            value = constant ^ value
        elif op == "mul":
            value = (constant * value) % MOD
    return value == target


def maybe_run_binary(binary: str, candidate: int) -> None:
    if not os.access(binary, os.X_OK):
        print(f"[i] {binary} is not executable, skipping live verification")
        return

    result = subprocess.check_output(
        [binary],
        input=f"{candidate}\n",
        text=True,
    )
    print("[i] Binary output:")
    print(result.rstrip())


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve the spidr reversing challenge")
    parser.add_argument("binary", nargs="?", default="chal", help="Path to the challenge binary")
    parser.add_argument(
        "--run",
        action="store_true",
        help="Run the binary with the recovered input after solving",
    )
    args = parser.parse_args()

    disassembly = run_objdump(args.binary)
    functions = parse_functions(disassembly)
    entry_func, target = parse_main(functions["main"])
    operations = flatten_operations(functions, entry_func)
    candidate = invert_operations(operations, target)

    if not verify_forward(operations, candidate, target):
        raise RuntimeError("Forward verification failed")

    print(f"[+] Entry function : {entry_func}")
    print(f"[+] Target value   : 0x{target:016x}")
    print(f"[+] Operations     : {len(operations)}")
    print(f"[+] Required input : {candidate}")
    print(f"[+] Flag           : grey{{{candidate}}}")

    if args.run:
        maybe_run_binary(args.binary, candidate)

    return 0


if __name__ == "__main__":
    sys.exit(main())
