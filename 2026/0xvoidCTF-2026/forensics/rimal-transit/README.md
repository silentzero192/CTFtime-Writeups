# Rimal Transit - Writeup

**Category:** `Forensics`  
**Flag:** `0xV01D{dns_frames_rebuilt_the_route_home}`

## Challenge Description

A pcap file containing network traffic that hints at data exfiltration via DNS queries. The flag format is `0xV01D{}`.

## Solution

### Initial Analysis

The pcap contains 28 DNS query packets, all sent to resolver `9.9.9.9`. There are no DNS responses — only outbound queries.

```
$ tshark -r rimal_transit.pcap -Y "dns" -T fields -e frame.number -e ip.src -e dns.qry.name
```

| Frame | Source IP | DNS Query |
|-------|-----------|-----------|
| 1     | 10.9.0.3  | `pxcbuexuic.cdn.invalid` |
| 2     | 10.9.0.13 | `03.bjrex4ssenf7fc6lkj.rimal-route.invalid` |
| 3     | 10.9.0.3  | `gwtvjmljvc.cdn.invalid` |
| ...   | ...       | ... |
| 27    | 10.9.0.222| `0xv01d.decoy.cache.invalid` |
| 28    | 10.9.0.223| `wrong-order.route-cache.invalid` |

Two interesting control packets stand out at the end:

- **Packet 27** (`10.9.0.222`): The query `0xv01d.decoy.cache.invalid` is explicitly labeled a **decoy**.
- **Packet 28** (`10.9.0.223`): The query `wrong-order.route-cache.invalid` tells us the **packets are in the wrong chronological order**.

### Two Query Groups

The queries fall into two groups:

**Group 1: `.cdn.invalid` queries** (20 packets from `10.9.0.3`)

Each carries a 10-character lowercase label:
```
pxcbuexuic, gwtvjmljvc, rxogejcnjb, szhcohnsky, vnxzihjlfq,
dlsaoxdvai, nbhryfvucb, cmnnebdvgw, azcmlkxcuv, hijjntzqan,
kbkkmgcraa, leohxxcvfu, wfnfjhhswp, zxmzluivne, spnqcbgpkw,
lzdkvwaknu, lljdwlomfs, haztytfucm, npwbcudggq, wqzrcsyagw
```

These appear to be padding/decoy traffic.

**Group 2: `.rimal-route.invalid` queries** (6 packets, each from a unique source IP)

Each query has a two-part label: a **sequence number** (00–05) followed by a longer alphanumeric string:

| Seq | Source IP | Label |
|-----|-----------|-------|
| 00  | 10.9.0.10 | `d6fqqaacoygguax7go` |
| 01  | 10.9.0.11 | `uaqmzqosuu5sjlrzhs` |
| 02  | 10.9.0.12 | `wswmjuwy4l2kjuvm3t` |
| 03  | 10.9.0.13 | `bjrex4ssenf7fc6lkj` |
| 04  | 10.9.0.14 | `rxh4rt2nvucqb3wbxo` |
| 05  | 10.9.0.15 | `zcsaaaaa` |

The source IPs are sequential (`10.9.0.10`–`10.9.0.15`), and the sequence number matches `last_octet - 10`. This confirms the intended ordering.

### Rebuilding the Data

The "wrong-order" clue means we must reorder the `.rimal-route.invalid` labels by their sequence number (00 → 05):

```python
labels = [
    "d6fqqaacoygguax7go",   # 00
    "uaqmzqosuu5sjlrzhs",   # 01
    "wswmjuwy4l2kjuvm3t",   # 02
    "bjrex4ssenf7fc6lkj",   # 03
    "rxh4rt2nvucqb3wbxo",   # 04
    "zcsaaaaa",              # 05
]
concatenated = "".join(labels)
# "d6fqqaacoygguax7gouaqmzqosuu5sjlrzhswswmjuwy4l2kjuvm3tbjrex4ssenf7fc6lkjrxh4rt2nvucqb3wbxozcsaaaaa"
```

The result is a 98-character string containing only lowercase letters and digits — characteristic of **Base32** encoding.

### Decoding

Base32 decoding, with appropriate padding, reveals gzip-compressed data (notice the magic bytes `\x1f\x8b\x08`):

```python
import base64
import gzip

padded = concat.upper()
# Pad to multiple of 8 for base32
padded += "=" * (8 - len(concat) % 8) if len(concat) % 8 else ""
compressed = base64.b32decode(padded)
# compressed starts with: 1f 8b 08 00 ... (gzip magic)

flag = gzip.decompress(compressed).decode()
print(flag)
# 0xV01D{dns_frames_rebuilt_the_route_home}
```

### Flag

```
0xV01D{dns_frames_rebuilt_the_route_home}
```

## Summary

| Step | Description |
|------|-------------|
| 1 | Identify DNS exfiltration in the pcap |
| 2 | Spot the "wrong-order" hint in packet 28 |
| 3 | Isolate `.rimal-route.invalid` queries and sort by sequence prefix |
| 4 | Concatenate labels in order (00–05) |
| 5 | Base32 decode the concatenated string |
| 6 | Gunzip the resulting compressed data |
| 7 | Read the flag |
