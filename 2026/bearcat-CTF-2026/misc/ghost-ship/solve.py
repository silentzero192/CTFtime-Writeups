#!/usr/bin/env python3
import argparse
import os
import re
import string
import subprocess
import sys
import tempfile
from pathlib import Path


C_PROBE_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <bf_file> <watch_ip>\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    int watch_ip = atoi(argv[2]);

    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *raw = (char *)malloc((size_t)sz + 1);
    if (!raw) {
        perror("malloc");
        fclose(f);
        return 1;
    }
    if (fread(raw, 1, (size_t)sz, f) != (size_t)sz) {
        perror("fread");
        fclose(f);
        free(raw);
        return 1;
    }
    fclose(f);

    char *code = (char *)malloc((size_t)sz + 1);
    if (!code) {
        perror("malloc");
        free(raw);
        return 1;
    }
    size_t n = 0;
    for (long i = 0; i < sz; i++) {
        char c = raw[i];
        if (c=='>' || c=='<' || c=='+' || c=='-' || c=='.' || c==',' || c=='[' || c==']') {
            code[n++] = c;
        }
    }
    free(raw);

    int *jmp = (int *)malloc(sizeof(int) * n);
    int *stack = (int *)malloc(sizeof(int) * n);
    if (!jmp || !stack) {
        perror("malloc");
        free(code);
        free(jmp);
        free(stack);
        return 1;
    }

    int sp = 0;
    for (size_t i = 0; i < n; i++) {
        if (code[i] == '[') {
            stack[sp++] = (int)i;
        } else if (code[i] == ']') {
            if (sp <= 0) {
                fprintf(stderr, "unmatched ] at %zu\n", i);
                free(code);
                free(jmp);
                free(stack);
                return 1;
            }
            int j = stack[--sp];
            jmp[i] = j;
            jmp[j] = (int)i;
        }
    }
    if (sp != 0) {
        fprintf(stderr, "unmatched [\n");
        free(code);
        free(jmp);
        free(stack);
        return 1;
    }

    char input[4096];
    size_t inlen = fread(input, 1, sizeof(input), stdin);
    size_t inpos = 0;

    const int TAPE_SIZE = 2000000;
    uint8_t *tape = (uint8_t *)calloc((size_t)TAPE_SIZE, 1);
    if (!tape) {
        perror("calloc");
        free(code);
        free(jmp);
        free(stack);
        return 1;
    }

    int ptr = TAPE_SIZE / 2;
    size_t ip = 0;
    while (ip < n) {
        if ((int)ip == watch_ip) {
            printf("%u\n", (unsigned)tape[ptr]);
            free(tape);
            free(code);
            free(jmp);
            free(stack);
            return 0;
        }

        char c = code[ip];
        switch (c) {
            case '>': ptr++; break;
            case '<': ptr--; break;
            case '+': tape[ptr]++; break;
            case '-': tape[ptr]--; break;
            case '.': break;
            case ',': tape[ptr] = (inpos < inlen) ? (uint8_t)input[inpos++] : 0; break;
            case '[': if (tape[ptr] == 0) ip = (size_t)jmp[ip]; break;
            case ']': if (tape[ptr] != 0) ip = (size_t)jmp[ip]; break;
        }
        ip++;
    }

    fprintf(stderr, "watch_ip not reached\n");
    free(tape);
    free(code);
    free(jmp);
    free(stack);
    return 1;
}
"""


def build_probe(binary_path: Path) -> None:
    c_path = binary_path.with_suffix(".c")
    c_path.write_text(C_PROBE_SOURCE, encoding="ascii")
    cmd = ["gcc", "-O3", "-pipe", "-std=c11", str(c_path), "-o", str(binary_path)]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr.decode(errors="ignore"))
        raise SystemExit("failed to build C probe")


def get_bf_ops(path: Path) -> str:
    data = path.read_text(encoding="ascii")
    return "".join(ch for ch in data if ch in "><+-.,[]")


def score_candidate(probe_path: Path, bf_path: Path, watch_ip: int, candidate: str) -> int:
    proc = subprocess.run(
        [str(probe_path), str(bf_path), str(watch_ip)],
        input=candidate.encode("ascii"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    out = proc.stdout.decode("ascii", errors="ignore").strip()
    if not re.fullmatch(r"\d+", out):
        raise RuntimeError(f"unexpected probe output: {out!r}")
    return int(out)


def recover_flag(
    bf_path: Path,
    watch_ip: int,
    charset: str,
    prefix: str,
    suffix: str,
) -> str:
    ops = get_bf_ops(bf_path)
    input_len = ops.count(",")
    if input_len == 0:
        raise RuntimeError("no input reads found in challenge file")

    if len(prefix) + len(suffix) > input_len:
        raise RuntimeError("prefix + suffix longer than required input length")

    with tempfile.TemporaryDirectory() as td:
        probe_path = Path(td) / "bf_probe"
        build_probe(probe_path)

        guess = ["~"] * input_len
        for i, ch in enumerate(prefix):
            guess[i] = ch
        for i, ch in enumerate(suffix):
            guess[input_len - len(suffix) + i] = ch

        start = len(prefix)
        end = input_len - len(suffix)
        for idx in range(start, end):
            best_ch = None
            best_score = 10**9
            for ch in charset:
                guess[idx] = ch
                candidate = "".join(guess)
                sc = score_candidate(probe_path, bf_path, watch_ip, candidate)
                if sc < best_score:
                    best_score = sc
                    best_ch = ch
            guess[idx] = best_ch
            print(f"[+] pos {idx:02d} -> {best_ch!r}, score={best_score}")

        flag = "".join(guess)
        final_score = score_candidate(probe_path, bf_path, watch_ip, flag)
        print(f"[+] final mismatch score = {final_score}")
        return flag


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve BCCTF ghost_ship challenge")
    parser.add_argument(
        "--file",
        default="ghost_ship",
        help="Path to Brainfuck challenge file (default: ghost_ship)",
    )
    parser.add_argument(
        "--watch-ip",
        type=int,
        default=9098,
        help="Instruction pointer where mismatch counter is checked (default: 9098)",
    )
    parser.add_argument(
        "--charset",
        default="".join(chr(i) for i in range(32, 127)),
        help="Characters to brute-force per position (default: printable ASCII 32..126)",
    )
    parser.add_argument(
        "--prefix",
        default="BCCTF{",
        help="Known flag prefix (default: BCCTF{)",
    )
    parser.add_argument(
        "--suffix",
        default="}",
        help="Known flag suffix (default: })",
    )
    args = parser.parse_args()

    bf_path = Path(args.file)
    if not bf_path.exists():
        raise SystemExit(f"file not found: {bf_path}")

    try:
        flag = recover_flag(
            bf_path=bf_path,
            watch_ip=args.watch_ip,
            charset=args.charset,
            prefix=args.prefix,
            suffix=args.suffix,
        )
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr.decode(errors="ignore"))
        raise SystemExit("probe execution failed")

    print(f"\nFLAG: {flag}")


if __name__ == "__main__":
    main()
