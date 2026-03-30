#!/usr/bin/env python3
import argparse
import json
import math
import socket
import statistics
import time


HOST = "chals2.apoorvctf.xyz"
PORT = 13337
BLOCK_SIZE = 16
MAX_QUERIES = 10_000


class ChallengeClient:
    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.file = None

    def __enter__(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        banner = self.sock.recv(4096).decode(errors="replace").strip()
        self.file = self.sock.makefile("rwb", buffering=0)
        return self, banner

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.file is not None:
                self.file.close()
        finally:
            if self.sock is not None:
                self.sock.close()

    def request(self, payload: dict):
        data = json.dumps(payload, separators=(",", ":")).encode() + b"\n"
        t0 = time.perf_counter_ns()
        self.file.write(data)
        line = self.file.readline()
        dt_ns = time.perf_counter_ns() - t0
        if not line:
            raise EOFError("server closed the connection")
        return json.loads(line.decode()), dt_ns


def bsc_capacity_bits_per_query(crossover: float) -> float:
    if crossover <= 0.0 or crossover >= 1.0:
        return 1.0
    h2 = -(crossover * math.log2(crossover) + (1.0 - crossover) * math.log2(1.0 - crossover))
    return 1.0 - h2


def probe_remote(host: str, port: int, samples: int, timeout: float):
    with ChallengeClient(host, port, timeout=timeout) as (client, banner):
        enc, _ = client.request({"option": "encrypt"})
        if "ct" not in enc:
            raise RuntimeError(f"unexpected encrypt response: {enc!r}")

        full_ct = bytes.fromhex(enc["ct"])
        if len(full_ct) != 3 * BLOCK_SIZE:
            raise RuntimeError(f"unexpected ciphertext length: {len(full_ct)} bytes")

        single_block_ct = full_ct[: 2 * BLOCK_SIZE].hex()

        true_count = 0
        false_count = 0
        timings_ms = []
        for _ in range(samples):
            resp, dt_ns = client.request({"option": "unpad", "ct": single_block_ct})
            if "result" not in resp:
                raise RuntimeError(f"unexpected unpad response: {resp!r}")
            if resp["result"]:
                true_count += 1
            else:
                false_count += 1
            timings_ms.append(dt_ns / 1_000_000.0)

        return {
            "banner": banner,
            "ciphertext_bytes": len(full_ct),
            "probes": samples,
            "true_rate": true_count / samples,
            "false_rate": false_count / samples,
            "rtt_mean_ms": statistics.mean(timings_ms),
            "rtt_median_ms": statistics.median(timings_ms),
            "rtt_stdev_ms": statistics.pstdev(timings_ms),
        }


def format_report(host: str, port: int, samples: int, timeout: float):
    report = probe_remote(host, port, samples, timeout)
    capacity = bsc_capacity_bits_per_query(0.45)
    max_information = capacity * MAX_QUERIES

    lines = []
    lines.append(f"remote: {host}:{port}")
    lines.append(f"banner: {report['banner']}")
    lines.append(f"encrypt returned {report['ciphertext_bytes']} bytes (expected 48)")
    lines.append(
        "known-invalid probe on IV||C1: "
        f"true_rate={report['true_rate']:.4f}, false_rate={report['false_rate']:.4f}"
    )
    lines.append(
        "round-trip timing over "
        f"{samples} probes: mean={report['rtt_mean_ms']:.3f} ms, "
        f"median={report['rtt_median_ms']:.3f} ms, stdev={report['rtt_stdev_ms']:.3f} ms"
    )
    lines.append("")
    lines.append("local-source feasibility check:")
    lines.append("- secret entropy: 128 bits (urandom(16).hex())")
    lines.append("- noisy oracle crossover after inversion: 0.45")
    lines.append(f"- channel capacity: {capacity:.9f} bits/query")
    lines.append(f"- 10,000-query upper bound: {max_information:.6f} bits")
    lines.append("")
    lines.append(
        "Conclusion: if the remote matches the provided source, the padding oracle alone "
        "cannot recover the 128-bit message before the query cap. A working exploit would "
        "need an extra leak that is not present in challenge.py."
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Probe the Domino Effect challenge and report whether the provided source is solvable."
    )
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", default=PORT, type=int)
    parser.add_argument("--samples", default=128, type=int)
    parser.add_argument("--timeout", default=10.0, type=float)
    args = parser.parse_args()

    print(format_report(args.host, args.port, args.samples, args.timeout))


if __name__ == "__main__":
    main()
