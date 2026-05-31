# Fort Knockies

**Category:** `Forensics`  

**Description:**    

> `hey i make a local password manager check it out`  

Flag: `grey{jz_some_rookie_mistakesi9v2k}`

## Overview

This challenge did not unpack into a normal app source tree. Instead, the provided files were an OCI container image layout:

- `manifest.json`
- `index.json`
- `oci-layout`
- `blobs/sha256/...`

That immediately suggests a container-forensics workflow rather than ordinary file carving. The goal is to reconstruct what the image used to contain, inspect deleted layers carefully, and recover anything that may still be left behind in earlier filesystem snapshots.

The key idea is that container layers are append-only. Even if a file is removed in a later layer, the older layer usually still contains it.

## Step 1: Identify what the image is

The root `manifest.json` describes the layer ordering:

```bash
python3 - <<'PY'
import json
manifest = json.load(open('manifest.json'))[0]
for i, layer in enumerate(manifest['Layers']):
    print(i, layer)
PY
```

This gives the ordered gzip-compressed tar layers under `blobs/sha256/`.

The image config metadata also tells us what happened during the build:

```bash
python3 - <<'PY'
import json
cfg = json.load(open('blobs/sha256/99d9e98b162f8066acf9778a1e0849140e6213af276de2714c5c2f103c941310'))
for i, h in enumerate(cfg['history']):
    print(i, h.get('created_by', ''))
PY
```

The important history entries were:

- `COPY /build/out/dev/.env /app/.env`
- `RUN rm -f /app/.env`
- `COPY /build/out/logs/ /var/lib/fortknockies/logs/`
- `COPY /build/out/late/ /`
- `RUN rm -rf /app/.git /var/lib/fortknockies/.staging`

That is already a huge clue:

- `.env` once existed and was later deleted
- `.git` once existed and was later deleted
- `.staging` once existed and was later deleted

Those are exactly the kinds of leftovers we want.

## Step 2: Inspect the interesting layers

Listing the later layers shows what each one contributed:

```bash
tar -tzf blobs/sha256/ccde7c866f5f00cea404aa1b3257669d0a640ca09f7c07b89fde08d23e122e2a
tar -tzf blobs/sha256/d8f983b0e2fb243440f23043d4d444d6487d85b0caad1306ed794bd672b4e8ab
tar -tzf blobs/sha256/3bf931e141bf5ac4933c2e236cf59d62cdf461bb8afe4046f0bd4d4f6b8e9a8b
tar -tzf blobs/sha256/6d537ffd9bd554ee61b9477db959fa1efbc7116bbb1b64f7963f3ca07a5a199c
```

Relevant results:

- `ccde...` contains `app/.env`
- `d8f9...` contains `var/lib/fortknockies/logs/fortknockies.log`
- `3bf9...` contains `app/.git/...` and `var/lib/fortknockies/.staging/README`
- `6d53...` contains whiteout files deleting `.git` and `.staging`

So the deleted artifacts are preserved in `3bf9...`.

## Step 3: Read the deleted `.env`

Extracting the deleted `.env`:

```bash
tar -xOzf blobs/sha256/ccde7c866f5f00cea404aa1b3257669d0a640ca09f7c07b89fde08d23e122e2a app/.env
```

Contents:

```text
FLASK_ENV=production
UPLOAD_LIMIT=8388608
SEAL_FORMAT=FKENC1

pycache
```

This is unusual: the final line is just `pycache`, not a normal `KEY=value` entry. It looks accidental, but accidental leftovers are often the point in forensics challenges.

At this stage `pycache` is suspicious, but not enough on its own.

## Step 4: Recover the deleted git repository

The deleted `.git` directory can be extracted from the same layer:

```bash
mkdir -p /tmp/fortknockies_repo
tar -xzf blobs/sha256/3bf931e141bf5ac4933c2e236cf59d62cdf461bb8afe4046f0bd4d4f6b8e9a8b -C /tmp/fortknockies_repo
cd /tmp/fortknockies_repo/app
git log --oneline
```

Recovered commits:

```text
cf02dfb remove legacy scratch files
446b2d6 add path mode test
e08083d keep legacy import notes
c5ee59e initial rookie test app
```

Important recovered files:

- old `README.md`
- `scratch_crypto.py`
- `tests/test_parts.py`
- `notes/todo.md`

The old README reveals that legacy bundles still existed:

```text
legacy seal mode is still around for imported handoff bundles
```

The deleted `scratch_crypto.py` gives the old decryption logic:

```python
def open_fkenc0(blob, password):
    ...
    key = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,
        salt=salt,
        iterations=64000
    ).derive(password.encode())
    ...
```

So there are two formats:

- current format: `FKENC1`
- legacy format: `FKENC0`

Then the best clue appears in the deleted test file:

```bash
git show 446b2d6:tests/test_parts.py
```

Output:

```python
part2 = "PATH"
```

In the next commit, that was replaced by:

```python
# moved into local config during build testing
```

That comment matters a lot. It implies:

- one password fragment was `PATH`
- another fragment was moved into local config

And we already found a suspicious leftover in local config: `pycache`

At this point, the likely assembled secret becomes:

`pycache` + `PATH` = `pycachePATH`

## Step 5: Inspect the deleted staging bundle

The layer also contains:

- `var/lib/fortknockies/.staging/README`

That looks harmless, but file type inspection shows it is actually a 7z archive:

```bash
7z l /tmp/fortknockies_repo/var/lib/fortknockies/.staging/README
```

Archive contents:

```text
flag.enc
sample-upload.enc
```

Extract them:

```bash
mkdir -p /tmp/fort_stage/extract
7z x /tmp/fortknockies_repo/var/lib/fortknockies/.staging/README -o/tmp/fort_stage/extract
```

Now inspect the encrypted files.

`flag.enc` starts with:

```json
{
  "version": "FKENC0",
  "kdf": "PBKDF2-HMAC-SHA1",
  "iterations": 64000,
  "cipher": "AES-256-CBC",
  ...
}
```

`sample-upload.enc` starts with:

```json
{
  "version": "FKENC1",
  "filename": "sample.txt",
  "kdf": "PBKDF2-HMAC-SHA256",
  "iterations": 250000,
  "cipher": "AES-256-GCM",
  ...
}
```

So:

- `sample-upload.enc` is from the current upload flow
- `flag.enc` is a legacy handoff bundle

That matches the deleted README and scratch decryptor perfectly.

## Step 6: Decrypt with the reconstructed password

Using the clues:

- local config artifact: `pycache`
- deleted test fragment: `PATH`

We try `pycachePATH`.

The following script decrypts both formats and verifies the candidate:

```python
import json
import base64
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def dec_fkenc0(path, password):
    env = json.load(open(path))
    salt = base64.b64decode(env["salt_b64"])
    iv = base64.b64decode(env["iv_b64"])
    ct = base64.b64decode(env["ciphertext_b64"])
    key = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,
        salt=salt,
        iterations=env["iterations"],
    ).derive(password.encode())
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpad = padding.PKCS7(128).unpadder()
    return unpad.update(padded) + unpad.finalize()


def dec_fkenc1(path, password):
    env = json.load(open(path))
    salt = base64.b64decode(env["salt_b64"])
    nonce = base64.b64decode(env["nonce_b64"])
    ct = base64.b64decode(env["ciphertext_b64"])
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=env["iterations"],
    ).derive(password.encode())
    return AESGCM(key).decrypt(nonce, ct, None)


password = "pycachePATH"
print(dec_fkenc0("/tmp/fort_stage/extract/flag.enc", password).decode())
print(dec_fkenc1("/tmp/fort_stage/extract/sample-upload.enc", password).decode())
```

Output:

```text
grey{jz_some_rookie_mistakesi9v2k}
sample upload: nothing interesting here
```

## Why this works

The challenge is built around “rookie mistakes” in containerized app delivery:

- copying secrets into the image during build
- deleting them later and assuming they are gone
- shipping `.git` history into the image
- leaving meaningful build comments in deleted source
- keeping a hidden staging bundle inside the image
- using a disguised archive file
- accidentally exposing a password fragment in `.env`

Even though the final filesystem looked cleaned up, the layer history preserved enough context to reconstruct the secret.

## Final flag

`grey{jz_some_rookie_mistakesi9v2k}`
