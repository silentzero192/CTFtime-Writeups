# GreyCat Game — CTF Challenge Writeup

**Challenge Name:** `GreyCat Game`  
**Category:** `Web`  
**Flag:** `grey{th3_trex_rep1ac3d_by_a_gr3y_cat}`

---

## Description

> This game looks familiar... but something is a little off(?)

We are given a web-based runner game (think Chrome's T-Rex game) hosted at `challs.nusgreyhats.org:34467`. No source files are provided — everything must be reverse-engineered from the browser.

---

## Reconnaissance

Visiting the page shows a canvas-based platformer. The HTML source contains a hint:

```html
<div class="terrain-meta" aria-hidden="true">
  <span data-scrap="grey{hop_hop_"></span>
  <span data-scrap="like_the_"></span>
  <span data-scrap="trex}"></span>
</div>
```

And the overlay subtitle reads:

> "Flags rarely sit in the foreground."

This immediately signals that the visible `data-scrap` fragments are **decoys**. The real flag is hidden deeper.

---

## Source Code Analysis

Two assets are loaded: `styles.css` and `game.js`.

### CSS — Pseudo-Element Flag Fragment

In `styles.css`, CSS custom properties define what looks like another flag fragment:

```css
--ghost-frag-a: "grey{";
--ghost-frag-b: "greycat_";
--ghost-frag-c: "run_";
--ghost-frag-d: "on_";
--ghost-frag-e: "2s}";
```

Concatenated: `grey{greycat_run_on_2s}` — another decoy.

### JavaScript — The Real Mechanism

`game.js` contains several interesting structures:

#### 1. Fake flags in source

```js
const challengeState = {
  flags: [
    "grey{you_better_run_bruno_cat}",
  ],
  // ...
};
```

This flag is rendered as a watermark text on obstacles (`obstacle.tag`). Another decoy.

#### 2. LocalStorage debug data

```js
localStorage.setItem(DEBUG_KEY, JSON.stringify({
  skylineNoise: [
    "scanline",
    "packet",
    "replay",
    "fragment:transit_",
    "grey{never_back_down_never_WHAT}",
  ],
  checksum: challengeState.frameChecksum,
}));
```

Yet another decoy.

#### 3. Server API Endpoints

The game communicates with several endpoints:

| Endpoint | Parameters | Purpose |
|---|---|---|
| `/api/bootstrap` | — | Returns session ID and `fastPhaseScore` threshold (2250) |
| `/api/run` | `score`, `tick`, `state` | Reports game progress; server validates physics |
| `/api/ghost` | `score`, `lane` | Returns XOR-encrypted flag fragments (requires `X-Runner-Debug: trace` and score ≥ 2250) |
| `/api/replay` | `view` | Returns session summary/replay data |

#### 4. Flag Fragment Revelation

Once the player's score reaches ≥ 2250 (`isFastPhase()`), the game periodically calls `/api/ghost`:

```js
async function revealFlagFragment() {
  const lane = game.spectralFragments.length % 2;
  const response = await fetch(
    `/api/ghost?score=${Math.floor(game.score)}&lane=${lane}`,
    { headers: { "X-Runner-Debug": "trace" } }
  );
  const payload = await response.json();
  const resolvedText = decodeStamp(payload.stamp, payload.traceId);
  // renders as faint text on canvas
}
```

The `decodeStamp` function decrypts the returned stamp using XOR:

```js
function decodeStamp(stamp, traceId) {
  const encoded = atob(stamp);
  const parts = traceId.split("-");
  const seed = parts[1];           // e.g. "5c730cdc"
  const index = Number(parts[2]) - 1;
  const keyBase = seed.split("").reduce((sum, ch) => sum + ch.charCodeAt(0), 0)
                  + Math.max(0, index) * 17;

  let output = "";
  for (let i = 0; i < encoded.length; i++) {
    const code = encoded.charCodeAt(i) ^ ((keyBase + i * 13) & 0xff);
    output += String.fromCharCode(code);
  }
  return output;
}
```

---

## Exploitation Strategy

The server validates that reported scores follow the game's physics. Simulating the exact game loop is necessary.

### Game Physics

- Score increments per tick: `0.24 × speed`
- `speed = min(28, 7 + score / 180)`
- Reports are sent every 24 ticks via `reportRunProgress()`

The differential equation:

```
dS/dt = 0.24 × (7 + S/180)      for S < 3780
dS/dt = 0.24 × 28 = 6.72         for S ≥ 3780
```

### Solver Script

The script simulates the game tick-by-tick, reports progress to `/api/run`, and once score ≥ 2250, fetches ghost fragments from `/api/ghost` with the required header.

```python
import requests
import base64
import math

session = requests.Session()
BASE = "http://challs.nusgreyhats.org:34467"

score = 0.0
tick = 0
speed = 7.0
last_report = -24

while tick < 2000:
    tick += 1
    score += 0.24 * speed
    speed = min(28, 7 + score / 180)

    if tick - last_report >= 24:
        last_report = tick
        r = session.get(f"{BASE}/api/run", params={
            "score": math.floor(score),
            "tick": tick,
            "state": "running"
        })

        if math.floor(score) >= 2250:
            r = session.get(f"{BASE}/api/ghost", params={
                "score": math.floor(score), "lane": 0
            }, headers={"X-Runner-Debug": "trace"})
            data = r.json()
            if data.get("stamp"):
                print(f"Got stamp: {data['stamp']} trace: {data['traceId']}")
```

### Decrypting Stamps

Each ghost response contains a `stamp` (base64) and `traceId` (e.g., `ghost-5c730cdc-1`). The XOR key is derived from:

```
seed = traceId.split("-")[1]      # "5c730cdc"
index = traceId.split("-")[2] - 1 # 0, 1, 2, ...
keyBase = sum(ord(c) for c in seed) + index * 17
```

Decoding implementation:

```python
import base64

def decode_stamp(stamp, trace_id):
    encoded = base64.b64decode(stamp)
    parts = trace_id.split("-")
    seed = parts[1]
    index = int(parts[2]) - 1
    key_base = sum(ord(c) for c in seed) + index * 17

    output = ""
    for i, ch in enumerate(encoded):
        code = ch ^ ((key_base + i * 13) & 0xFF)
        output += chr(code)
    return output
```

---

## The Flag

Running the solver produces 6 ghost fragments that reassemble into the flag:

| Stamp | Trace ID | Decrypted |
|---|---|---|
| `OxsT+uvpwoSb` | `ghost-5c730cdc-1` | `grey{t` |
| `GQji7P4=` | `ghost-5c730cdc-2` | `h3_tr` |
| `DO7olNPc/725` | `ghost-5c730cdc-3` | `ex_rep` |
| `7eX215w=` | `ghost-5c730cdc-4` | `1ac3d` |
| `x9+Jvos=` | `ghost-5c730cdc-5` | `_by_a` |
| `0t+/pQ==` | `ghost-5c730cdc-6` | `_gr3y_cat}` |

**Concatenated: `grey{th3_trex_rep1ac3d_by_a_gr3y_cat}`**

---

## Summary

This was a multi-layered web challenge with a fake-flag decoy chain:

1. **Layer 1 (HTML):** `data-scrap` attributes — `grey{hop_hop_like_the_trex}` ❌
2. **Layer 2 (CSS):** CSS custom properties — `grey{greycat_run_on_2s}` ❌
3. **Layer 3 (JS source):** `challengeState.flags` — `grey{you_better_run_bruno_cat}` ❌
4. **Layer 4 (LocalStorage):** Debug key — `grey{never_back_down_never_WHAT}` ❌
5. **Layer 5 (Runtime API):** XOR-encrypted ghost fragments — `grey{th3_trex_rep1ac3d_by_a_gr3y_cat}` ✅

The real flag only reveals itself after the server validates a legitimate game session reaching score ≥ 2250, and the XOR-encrypted fragments are decrypted using the `traceId` as the key derivation seed.
