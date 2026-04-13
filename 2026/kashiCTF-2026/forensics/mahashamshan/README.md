# Mahashamshan Writeup

## Challenge

- **Name:** `mahashamshan`
- **Category:** Forensics
- **File:** `mahashamshan_2.pcap`
- **Flag:** `kashiCTF{fr4g_b1t5_4r3_my_5ecr3t_c4rr13r}`

> A packet capture was pulled from a compromised node inside a covert communications network. The operator who extracted it left only one note before going dark:
>
> "The river does not reveal itself. It only flows."
>
> Your tools will lie to you. Your instincts will betray you. There are many ragebaits. There are fake helpers too becareful. It has always been in the packets. "Not all fields are what they seem. The fragment offset field hides more than offset."

## TL;DR

The PCAP contains multiple intentional bait channels.

- The DNS traffic decodes to a very clean-looking fake flag: `kashiCTF{n0th1ng_t0_s33_h3r3_c1d}`
- A second TCP stream to `172.31.0.1:8443` also carries garbage / decoy-looking characters
- The real flag is hidden in packets to `10.13.37.1`

The important trick is that those packets claim to be IP fragments with `ip.frag_offset = 5`, so normal tooling does not decode the TCP header fields properly. If you ignore that lie and parse `data.data` manually as a full TCP segment, the hidden structure becomes obvious:

- `src_port = 10000 + 37 * index`
- `seq = 123456 * index`
- `(ip.id & 0xff) ^ 0x21 = character`

Sort by `index`, decode each character, and you get the real flag.

---

## 1. Initial Recon

Start with the usual triage:

```bash
capinfos mahashamshan_2.pcap
tshark -r mahashamshan_2.pcap -q -z io,phs
tshark -r mahashamshan_2.pcap -q -z conv,ip
```

### What stands out

- The capture is small: `216` packets
- Main talking host: `192.168.7.77`
- Interesting destinations:
  - `10.13.37.1`
  - `172.31.0.1`
  - `1.1.1.1`
  - `8.8.8.8`
- Protocol mix:
  - TCP
  - ICMP
  - UDP/DNS

That already matches the prompt: lots of places to get baited.

---

## 2. First Round of Suspicious Channels

### 2.1 DNS traffic to `8.8.8.8`

Extract the queried names:

```bash
tshark -r mahashamshan_2.pcap -Y "dns" -T fields -e dns.id -e dns.qry.name
```

The first label of each query is base64:

```text
0x0003  M19jMWR9.telemetry.corp-internal.net
0x0000  a2FzaGlDVEZ7.telemetry.corp-internal.net
0x0002  MF9zMzNfaDNy.telemetry.corp-internal.net
0x0001  bjB0aDFuZ190.telemetry.corp-internal.net
```

Decoding and ordering by DNS transaction ID gives:

```text
kashiCTF{n0th1ng_t0_s33_h3r3_c1d}
```

This looks perfect, which is exactly why it is suspicious.

The challenge explicitly warns:

- fake helpers exist
- tools will lie
- the fragment offset field matters

So this DNS flag is a deliberate decoy.

### 2.2 TCP packets to `172.31.0.1:8443`

There is also a stream with tiny 4-byte payloads:

```bash
tshark -r mahashamshan_2.pcap -Y "ip.dst==172.31.0.1" -T fields -e frame.number -e tcp.srcport -e data.data
```

If you take the first byte from each payload in time order, you get:

```text
t3{rT31_l1sk_arC40ui}shn_p_1Fg
```

That is another bait channel. It looks “almost meaningful”, but not enough to be the final answer.

### 2.3 ICMP to `1.1.1.1`

The ICMP payloads contain bytes that look partially structured and partially random. They contain teaser-looking fragments such as `kash` / `iCTF`, but they never cleanly resolve into a complete flag. Another ragebait.

---

## 3. The Real Hint: Bogus Fragmented Packets

The prompt says:

> Not all fields are what they seem. The fragment offset field hides more than offset.

This points directly at packets going to `10.13.37.1`.

Try extracting a few fields:

```bash
tshark -r mahashamshan_2.pcap \
  -Y "ip.dst==10.13.37.1" \
  -T fields \
  -e frame.number \
  -e ip.id \
  -e ip.frag_offset \
  -e tcp.srcport \
  -e tcp.dstport \
  -e data.data
```

You will notice something strange:

- `ip.frag_offset` is always `5`
- `tcp.srcport` / `tcp.dstport` are blank
- `data.data` starts with bytes that clearly look like a TCP header

Example:

```text
3   0x4a58   5       2a8801bb002d3600000000005018200000000000504f5354202f6170692f76312f73796e6320485454502f312e310d0a...
```

Now decode the first few bytes manually:

```text
2a88  -> source port = 10888
01bb  -> destination port = 443
002d3600 -> sequence number
00000000 -> ack number
5018 -> TCP data offset / flags
```

So Wireshark is refusing to interpret the TCP header normally because it trusts the IP fragmentation metadata. But the payload itself still contains a complete TCP segment.

This is the core trick of the challenge.

---

## 4. Manual Parsing of the Fake Fragment Stream

Let us parse those packets ourselves.

### 4.1 Extract the raw “TCP” bytes

```bash
tshark -r mahashamshan_2.pcap \
  -Y "ip.dst==10.13.37.1" \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.id \
  -e data.data
```

### 4.2 Interpret the first 20 bytes as a TCP header

Using Python:

```python
import struct

b = bytes.fromhex("2a8801bb002d3600000000005018200000000000")
src, dst, seq, ack, off_flags, win, csum, urg = struct.unpack("!HHIIHHHH", b)

print(src)  # 10888
print(dst)  # 443
print(seq)  # 2962944
```

When you do this for all packets to `10.13.37.1`, two patterns jump out immediately:

### 4.3 Hidden packet index

For each packet:

```text
index = (src_port - 10000) / 37
```

This produces every integer from `0` to `40`, exactly once.

The TCP sequence number also encodes the same value:

```text
seq = 123456 * index
```

So every packet carries both:

- a position
- one encoded character

### 4.4 Hidden character

Take the low byte of `ip.id`, then XOR with `0x21`:

```text
character = chr((ip.id & 0xff) ^ 0x21)
```

Examples:

```text
0x624a -> 0x4a ^ 0x21 = 0x6b = 'k'
0x6140 -> 0x40 ^ 0x21 = 0x61 = 'a'
0x6052 -> 0x52 ^ 0x21 = 0x73 = 's'
0x5f49 -> 0x49 ^ 0x21 = 0x68 = 'h'
0x5e48 -> 0x48 ^ 0x21 = 0x69 = 'i'
```

That already starts with `kashi`, which is the confirmation we need.

---

## 5. Full Solver

This script reconstructs the flag directly from the real channel:

```python
import subprocess
import struct

cmd = [
    "tshark",
    "-r", "mahashamshan_2.pcap",
    "-Y", "ip.dst==10.13.37.1",
    "-T", "fields",
    "-e", "ip.id",
    "-e", "data.data",
]

out = subprocess.check_output(cmd, text=True).strip().splitlines()

parts = []
for line in out:
    ipid, hexdata = line.split("\t")
    b = bytes.fromhex(hexdata)

    src, dst, seq, ack, off_flags, win, csum, urg = struct.unpack("!HHIIHHHH", b[:20])

    index = (src - 10000) // 37
    ch = chr((int(ipid, 16) & 0xff) ^ 0x21)
    parts.append((index, ch))

parts.sort()
flag = "".join(ch for _, ch in parts)
print(flag)
```

Output:

```text
kashiCTF{fr4g_b1t5_4r3_my_5ecr3t_c4rr13r}
```

---

## 6. Why the DNS Flag Is Fake

This challenge is built around misdirection, so it is worth calling this out explicitly.

The DNS flag:

```text
kashiCTF{n0th1ng_t0_s33_h3r3_c1d}
```

is intentionally attractive because:

- it is easy to extract
- it already matches the flag format
- it decodes cleanly with standard tooling

But the author practically tells us not to trust the easy path:

- “Your tools will lie to you”
- “There are fake helpers too”
- “The fragment offset field hides more than offset”

That makes the DNS channel a textbook fake helper.

---

## 7. Final Flag

```text
kashiCTF{fr4g_b1t5_4r3_my_5ecr3t_c4rr13r}
```

---

## 8. Takeaways

- If a challenge says your tools lie, verify raw bytes yourself.
- If IP fragmentation metadata looks weird, do not trust higher-layer dissection blindly.
- Repeated “too easy” channels in a forensics CTF are often bait.
- Here, the fragment offset was not carrying the flag directly. It was the clue that told us the packet parser was being manipulated.

