# Flags - Writeup

## Challenge Info

| Field | Value |
| --- | --- |
| Name | `flags` |
| Category | Web |
| Description | `you may have the flag` |
| Target | `http://34.126.223.46:18461` |
| Flag Format | `kashiCTF{...}` |

## TL;DR

The application looked like a simple "locked until later" page, but the lock logic trusted a client-controlled `X-Time` HTTP header. By sending a future timestamp, the countdown check was bypassed and the server returned the flag directly.

## Initial Recon

Visiting the challenge root returned a minimal Express response:

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8

<h2>Challenge Locked</h2>
<p>Opens in ~731 minutes</p>
```

Important observations:

1. The app is running on `Express`.
2. The site has only one obvious route, `/`.
3. The content strongly suggests some kind of time-based gate.

I also checked the usual easy wins:

- `robots.txt`
- `/flag`
- `/admin`
- `/favicon.ico`
- `OPTIONS /`
- common hidden paths and static files

Nothing useful showed up. Most alternate paths returned standard Express 404 pages like:

```text
Cannot GET /flag
```

## Why the Root Page Was Suspicious

The challenge page was too small and too specific to be the whole challenge. It did not contain:

- any frontend JavaScript,
- any form inputs,
- any static asset references,
- any obvious hidden routes,
- or any meaningful response changes for normal query parameters.

That pointed to the bug being in request handling itself rather than in a hidden page.

## Black-Box Testing Strategy

Since the site revolved around time, I tested whether the app trusted any client-controlled values related to:

- date/time headers,
- timezone headers,
- cookies,
- query parameters,
- and alternate request formats.

Most of these had no effect:

- `Date`
- `X-Date`
- `X-Timezone`
- `X-Timezone-Offset`
- `?date=...`
- `?time=...`
- cookies like `unlock=1`, `preview=1`, `admin=1`

The page always stayed in the same locked state.

## Finding the Useful Header

At that point I fuzzed header names on the `/` route to see whether any custom header changed the response.

Using a small header name list with `ffuf`:

```bash
ffuf -u http://34.126.223.46:18461/ \
  -H 'FUZZ: 1' \
  -w /tmp/flags_xheaders.txt \
  -mc all -fs 66
```

This produced one interesting result:

```text
x-time  [Status: 200, Size: 71]
```

That was the first real branch in behavior.

## Confirming the Time Injection

When I sent a low numeric value:

```bash
curl -i -sS -H 'X-Time: 1' http://34.126.223.46:18461/
```

the server responded with:

```text
<h2>Challenge Locked</h2>
<p>Opens in ~13282230 minutes</p>
```

So the app was clearly reading `X-Time` and using it in the countdown calculation.

Sending a garbage-large value:

```bash
curl -i -sS -H 'X-Time: 9999999999999' http://34.126.223.46:18461/
```

returned:

```text
<h2>Challenge Locked</h2>
<p>Opens in ~NaN minutes</p>
```

This confirms the application was unsafely parsing the header and feeding it directly into its time logic.

## Final Bypass

Once `X-Time` was identified, the natural next step was to supply a valid future timestamp so the app would think the challenge had already opened.

Working payload:

```bash
curl -i -sS -H 'X-Time: 2030-01-01T00:00:00Z' http://34.126.223.46:18461/
```

Response:

```text
kashiCTF{71m3_byp455_w45_fun_45_0AELZLBE}
```

No extra endpoint was required. The flag was returned directly from `/` once the time check passed.

## Flag

```text
kashiCTF{71m3_byp455_w45_fun_45_0AELZLBE}
```

## Root Cause

The backend trusted a client-controlled custom header:

```text
X-Time
```

Instead of using only the server's own clock, it appears to have parsed the header and used it for the gate condition. That made the lock completely bypassable by supplying a timestamp in the future.

## Why This Worked

- The challenge logic depended on time.
- The application accepted `X-Time` from the client.
- That header influenced the lock calculation directly.
- A future timestamp satisfied the "open" condition.
- The root route then returned the flag instead of the countdown page.

## Remediation

If this were a real application, the fixes would be straightforward:

1. Never trust client-supplied time headers for authorization or feature gating.
2. Always use the server clock for release windows and access control.
3. Reject unrecognized custom headers or ignore them entirely in critical logic.
4. Validate and sanitize parsed date values to avoid `NaN` behavior.

## Solver Notes

The hardest part of this challenge was not the exploit itself, but identifying the right input surface. The site looked almost empty, and most common web probes returned nothing useful. The breakthrough came from fuzzing custom headers and noticing that `X-Time` changed the response size, which immediately exposed the bug.
