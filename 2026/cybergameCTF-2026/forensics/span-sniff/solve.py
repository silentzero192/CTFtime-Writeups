#!/usr/bin/env python3
"""
CTF Challenge: span sniff
Platform: CyberGame CTF 2026
Category: Forensics
Flag format: SK-CERT{...}

Covert channel: HTTP Host header presence/absence (1/0 binary) → ASCII flag
"""

import subprocess
import sys

PCAP = "network.pcap"


def extract_host_bits(pcap_file: str) -> list[int]:
    """
    Extract all HTTP request packets and record whether the Host header
    is present (1) or absent (0).
    """
    result = subprocess.run(
        [
            "tshark", "-r", pcap_file,
            "-Y", "http.request",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "http.host",
        ],
        capture_output=True,
        text=True,
    )

    bits = []
    for line in result.stdout.strip().split("\n"):
        parts = line.split("\t")
        if len(parts) >= 1:
            host_field = parts[1].strip() if len(parts) > 1 else ""
            bits.append(1 if host_field else 0)

    return bits


def bits_to_ascii(bits: list[int]) -> str:
    """
    Convert a list of bits to ASCII text using 8-bit chunks.
    Non-printable bytes are shown as [val].
    """
    result = ""
    for i in range(0, len(bits) - 7, 8):
        byte_bits = bits[i : i + 8]
        val = int("".join(str(b) for b in byte_bits), 2)
        result += chr(val) if 32 <= val <= 126 else f"[{val}]"
    return result


def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else PCAP

    print(f"[*] Analysing: {pcap}")

    bits = extract_host_bits(pcap)
    print(f"[*] Total HTTP requests found : {len(bits)}")
    print(f"[*] Bits with Host header (1) : {bits.count(1)}")
    print(f"[*] Bits without Host header (0): {bits.count(0)}")
    print(f"[*] Raw bit stream  : {''.join(str(b) for b in bits)}")

    flag = bits_to_ascii(bits)
    print(f"\n[+] Decoded message : {flag}")

    # Isolate the SK-CERT{...} flag
    import re
    m = re.search(r"SK-CERT\{[^}]+\}", flag)
    if m:
        print(f"\n[FLAG] {m.group()}")
    else:
        print("\n[!] Flag pattern not found in decoded output.")


if __name__ == "__main__":
    main()
