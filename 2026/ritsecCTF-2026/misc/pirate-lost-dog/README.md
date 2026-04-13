# Pirate's Lost Dog

## Challenge

- Name: `pirate's lost dog`
- Category: `misc`
- Target zone: `linksnsec.stellasec.com`
- Important note from the prompt: the service answers on DNS over TCP only

## Goal

The description tells us almost everything we need:

1. The data is hidden in DNS.
2. The records form a breadcrumb trail.
3. The answer is the single record with the longest content.

That strongly suggests a DNSSEC/NSEC zone walk.

## Recon

Regular recursive lookups were not very helpful, so the first step was identifying the authoritative server for the zone.

Using trace:

```bash
dig +tcp +trace linksnsec.stellasec.com NS
```

This reveals the zone is served by:

```text
linksnsec.stellasec.com. NS linksnsecns.stellasec.com.
```

and the authoritative server resolves to:

```text
129.21.21.95
```

Direct queries to that server worked:

```bash
dig +tcp @129.21.21.95 linksnsec.stellasec.com SOA
dig +tcp @129.21.21.95 linksnsec.stellasec.com NS
```

AXFR was blocked, so a zone transfer was not possible:

```bash
dig +tcp @129.21.21.95 linksnsec.stellasec.com AXFR
```

## Why NSEC Walking Works

The zone is DNSSEC-signed with `NSEC`, not `NSEC3`.

Querying the apex `NSEC` record gives the next valid name in canonical order:

```bash
dig +tcp +short @129.21.21.95 linksnsec.stellasec.com NSEC
```

Output:

```text
000n96.linksnsec.stellasec.com. NS SOA RRSIG NSEC DNSKEY
```

That means:

- the next name after the zone apex is `000n96.linksnsec.stellasec.com`
- we can keep querying `NSEC` records to walk the whole zone

Following the chain:

```bash
dig +tcp +short @129.21.21.95 000n96.linksnsec.stellasec.com NSEC
```

gives:

```text
002xg1.linksnsec.stellasec.com. TXT RRSIG NSEC
```

and so on.

## Faster Enumeration

The main annoyance is that the challenge only answers over TCP. Spawning `dig` for every `NSEC` and every `TXT` query works, but it is slow.

The better approach was:

1. Open one TCP socket to the authoritative DNS server.
2. Send repeated DNS `ANY` queries over the same socket.
3. Parse both the `TXT` and `NSEC` answers from each response.

This avoids process overhead and cuts the walk to one query per name.

Core idea:

```python
import socket
import struct
import dns.message
import dns.rdatatype

SERVER = ("129.21.21.95", 53)
ZONE = "linksnsec.stellasec.com."

sock = socket.create_connection(SERVER, timeout=5)
sock.settimeout(5)

def recv_exact(n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError("socket closed")
        data += chunk
    return data

def query(name):
    msg = dns.message.make_query(name, "ANY")
    wire = msg.to_wire()
    sock.sendall(struct.pack("!H", len(wire)) + wire)
    size = struct.unpack("!H", recv_exact(2))[0]
    return dns.message.from_wire(recv_exact(size))

seen = set()
name = ZONE
best = (0, "", "")

while name not in seen:
    seen.add(name)
    response = query(name)

    nxt = None
    txt = ""

    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.TXT:
            for item in rrset:
                txt += "".join(part.decode() for part in item.strings)
        elif rrset.rdtype == dns.rdatatype.NSEC:
            nxt = rrset[0].next.to_text()

    if len(txt) > best[0]:
        best = (len(txt), name, txt)

    name = nxt

print(best)
```

## Result of the Full Walk

The full walk wrapped after `1002` names.

The longest TXT record in the entire zone was:

```text
67ljie.linksnsec.stellasec.com.
```

with content:

```text
thebartentersawcaptainjackwalkintothebarwiththeshipswheelaroundhisnutsthebartenderaskedhimwhatwasgoingoncaptainjackrepliedyaaritsdrivingmenuts
```

Length:

```text
142
```

This is exactly the outlier the prompt tells us to recover.

You can verify it directly:

```bash
dig +tcp @129.21.21.95 67ljie.linksnsec.stellasec.com TXT
```

## Flag

```text
RS{thebartentersawcaptainjackwalkintothebarwiththeshipswheelaroundhisnutsthebartenderaskedhimwhatwasgoingoncaptainjackrepliedyaaritsdrivingmenuts}
```

## Takeaway

This challenge is a classic DNSSEC zone-walking puzzle:

- `AXFR` is blocked
- `NSEC` still leaks the full ordered namespace
- TCP-only DNS makes naive enumeration slower
- reusing one TCP connection makes the walk practical

Once the zone is enumerated, the challenge reduces to selecting the single longest TXT payload.
