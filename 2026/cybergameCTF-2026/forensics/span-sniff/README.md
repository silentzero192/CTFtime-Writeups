# Span Sniff - Forensics Chall Writeup

**Challenge Name:** `span sniff`  
**Platform:** `CyberGame CTF 2026`  
**Category:** `Forensics`

## 1) Goal (What was the task?)

We were given a 16 MB PCAP file captured from a corporate network device after a suspected incident. The objective was to investigate the traffic and recover a flag in the format `SK-CERT{...}`.

---

## 2) Key Clues (What mattered?)

- **Challenge name → "span sniff"**: SPAN stands for *Switched Port Analyzer* — a network tap that mirrors all traffic on a switch. This hints that the capture contains mirrored traffic and a hidden covert channel.
- **`network.pcap`** — Linux cooked-mode capture v2 (SLL2), 7 753 packets, ~88 seconds.
- **HTTP traffic on port 8080** between `192.168.1.69` and `10.10.10.10` — lots of randomized methods (`GET/POST/PUT/DELETE/PATCH`) and endpoints (`/contact`, `/dashboard`, etc.).
- **296 HTTP requests** — all requests carry a JSON body with `user_id`, `session_id`, `device_id`, `timestamp`, and `action` fields.
- **Some HTTP requests include a `Host:` header; others do not** — this inconsistency stood out as the real signal.

---

## 3) Plan (Your first logical approach)

- Check the PCAP for any plaintext flag with `strings` and `tshark` keyword search → nothing found.
- Enumerate all protocols and identify any unusual traffic (TLS, SSH, HTTP) → flag not in TLS (encrypted), SSH only shows key exchange.
- Enumerate all known covert channels in HTTP: methods, response codes, Content-Length values, JSON field values → none decoded cleanly.
- Investigate **structural anomalies** in HTTP headers — the presence vs. absence of the `Host:` header looked binary and systematic → decode as ASCII.

---

## 4) Steps (Clean execution)

**Step 1 — Survey the PCAP**

```bash
capinfos network.pcap
tshark -r network.pcap -q -z io,phs
```

*Result:* 7 753 packets; protocols: TLS (to GitHub/Reddit/YouTube), SSH (key-exchange only), HTTP/JSON (port 8080). No DNS.

**Step 2 — Search for the flag in plaintext**

```bash
strings network.pcap | grep -i "SK-CERT"
```

*Result:* Nothing. Flag is hidden.

**Step 3 — Examine HTTP traffic structure**

```bash
tshark -r network.pcap -Y "http" -T fields \
  -e frame.number -e http.request.method \
  -e http.request.uri -e http.response.code
```

*Result:* 296 HTTP requests using random methods and endpoints; responses return 200/201/204. JSON bodies contain `user_id`, `session_id`, `device_id`, `timestamp`, `action`.

**Step 4 — Attempt covert channel decoding (eliminating false leads)**

| Field tested | Values seen | Decoded? |
|---|---|---|
| HTTP action (3-bit) | blur/click/focus/hover/scroll/submit/view | ❌ garbage |
| Response code (1-bit) | 200 / 201 / 204 | ❌ garbage |
| HTTP methods (3-bit) | DELETE/GET/PATCH/POST/PUT | ❌ garbage |
| Content-Length | 205 / 206 / 207 | ❌ just reflects action name length |
| IP ID, TCP ISN | random 32-bit | ❌ garbage |

**Step 5 — Spot the `Host` header anomaly**

```bash
tshark -r network.pcap -Y "http.request" -T fields \
  -e frame.number -e http.host
```

*Result:* Exactly 147 requests have `Host: 192.168.48.134:8080` and 149 do not — for 296 total. The presence (1) or absence (0) forms a binary stream.

**Step 6 — Decode Host-header presence as binary ASCII**

```python
# Map: Host present → 1, absent → 0
# Group into 8-bit chunks and decode as ASCII
```

*Result:* `SK-CERT{h1DD3n_1n_pl41n7eX7_n37Fl0w}`  ✅

---

## 5) Solution Summary (What worked and why?)

The attacker embedded a secret message by toggling the `Host:` HTTP header — present for bit `1`, absent for bit `0`. Across 296 requests, this produces a 296-bit stream. Reading it in 8-bit chunks and converting each byte to ASCII reveals the full flag. The technique is called **binary header-presence steganography** — it hides data in a structural (boolean) property of the protocol rather than in any payload value, making it invisible to simple string searches or content inspection.

---

## 6) Flag

```
SK-CERT{h1DD3n_1n_pl41n7eX7_n37Fl0w}
```

---

## 7) Lessons Learned

- **Check boolean header presence/absence** — required/optional HTTP headers (`Host`, `Accept-Encoding`, `Content-Type`) can carry single bits.
- **"Span sniff" = SPAN port tap** — the challenge name itself told us to look for a subtle covert channel in mirrored corporate traffic.
- **Eliminate noisy fields first** — values like JSON actions, response codes, and Content-Length may *look* like covert channels but correlate to legitimate data variations.
- **Structural anomalies beat value anomalies** — when values look random, pivot to *structural* properties (header present vs absent, field exists vs missing, connection established or not).

---

## 8) Personal Cheat Sheet

| Command / Pattern | Purpose |
|---|---|
| `tshark -Y "http.request" -T fields -e http.host` | Check which requests include a `Host` header |
| `tshark -q -z io,phs -r file.pcap` | Protocol hierarchy — fast overview |
| `strings file.pcap \| grep -i "FLAG_FORMAT"` | Quick plaintext flag search |
| `tshark -Y "http" -T fields -e http.content_length` | Spot Content-Length anomalies |
| **Pattern: boolean header presence → binary** | Any optional HTTP header can encode 1 bit per packet |
| **Pattern: challenge name = hint** | "span sniff" → SPAN port → covert channel in mirrored traffic |
| `capinfos file.pcap` | File summary: packet count, duration, encapsulation |
