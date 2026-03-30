# Door No. 8005 Writeup

Challenge Name: Door No. 8005  
Platform: UpSide CTF 2026  
Category: Web  
Difficulty: Easy  
Time spent: ~10 minutes

## 1) Goal (What was the task?)
The objective was to access a remote Hawkins terminal exposed on `140.245.25.63:8005`, find a way past the internal-only restriction, and recover the flag. Success meant interacting with the service and extracting the final flag in the `CTF{...}` format.

## 2) Key Clues (What mattered?)
- The prompt said `internal-only portal`, `maintenance hatch`, and `Door No. 8005 at 140.245.25.63`
- The target was an IP and port, which suggested probing the service directly instead of assuming a normal website
- The service did not behave like standard HTTP and responded more like an interactive terminal
- The logs leaked both the token generation method and Dr. Brenner's exact operator ID

## 3) Plan (Your first logical approach)
- Check whether the target is a normal HTTP or HTTPS web service.
- If it is not standard web traffic, inspect the raw service behavior directly.
- Enumerate menu options safely and read logs first because they often reveal secrets or weak authentication logic.
- Recreate the token locally and use it to access the admin path.

## 4) Steps (Clean execution)
1. I probed the target with `curl` over HTTP and HTTPS.
   Result: HTTPS failed, and HTTP returned `HTTP/0.9`-style behavior instead of a normal web page.
   Decision: Treat the challenge as a raw interactive network service rather than a browser-based site.

2. I queried the service with `curl --http0.9` and then opened a live session with `nc 140.245.25.63 8005`.
   Result: The service displayed a terminal interface and issued an access token for any username.
   Decision: Interact with the menu and inspect the least risky option first.

3. I chose option `1` to view the previous messages/logs.
   Result: The logs revealed the token scheme: take the username, append `1983`, and run MD5. The logs also disclosed that Brenner's operator ID was exactly `DrBrenner`.
   Decision: Forge Brenner's admin token locally instead of guessing credentials.

4. I generated the token for `DrBrenner1983`.
   Result: The MD5 hash was `43095647eb9196088480eab17e08605a`.
   Decision: Use this token in the admin validation path.

5. I selected option `3` and submitted the forged token.
   Result: The service responded with `ACCESS GRANTED. Welcome Dr. Brenner.`
   Decision: Revisit the logs after elevation because admin-only data is often stored there.

6. I chose option `1` again after gaining admin access.
   Result: The classified NINA logs were displayed and included the flag.
   Decision: Extract and verify the final `CTF{...}` value.

## 5) Solution Summary (What worked and why?)
The main weakness was broken authentication based entirely on a predictable token scheme. The service trusted an MD5 hash of `username + 1983`, and the logs directly disclosed both the token formula and Brenner's exact username. That meant there was no real secret left to discover, only a value to recompute. Once I forged the correct token for `DrBrenner`, the admin-only logs became accessible and revealed the flag.

## 6) Flag
`CTF{Dr_n0_br3nn3R}`

## 7) Lessons Learned (make it reusable)
- Do not assume every "web" challenge is a normal browser app; sometimes the real interface is a raw TCP service.
- If a service offers logs or status pages, check them early because they often leak implementation details.
- Predictable token schemes like `MD5(username + constant)` are not authentication, especially when both inputs can be discovered.
- When a port behaves strangely with HTTP, try raw interaction tools such as `nc`.

## 8) Personal Cheat Sheet (optional, but very useful)
- `curl -i http://host:port/` -> quick check for standard HTTP behavior
- `curl --http0.9 http://host:port/` -> useful when a service responds with old or unusual HTTP formatting
- `nc host port` -> interact directly with text-based TCP services
- `python3 -c "import hashlib; print(hashlib.md5(b'DrBrenner1983').hexdigest())"` -> compute a leaked MD5-based token
- Pattern: if logs mention how tokens are built, stop brute forcing and reproduce the logic locally
