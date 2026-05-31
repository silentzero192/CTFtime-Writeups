# Treasure Hunt

> **CTF:** tjCTF 2026  
> **Category:** Web  
> **Flag:** `tjctf{s1lv3r_and_g0ld}`

## Description

> Let's go hunt down some treasure! The flag is split into 4 parts. I'll give you the first one right here: `tjctf`

## Solution

The flag is split across 4 locations on the site. Each piece is discovered through simple web reconnaissance techniques.

### Part 1 — Given (`tjctf`)

The challenge description hands us the first piece: `tjctf`.

### Part 2 — Cookie (`{s1lv3r`)

Submitting the form on the homepage sends a **POST** request. The response sets a cookie:

```
silver_coffer={s1lv3r
```

This reveals `{s1lv3r`.

### Part 3 — Hidden HTML (`_and_`)

Viewing the homepage source reveals a hidden `<p>` element:

```html
<p hidden>_and_</p>
```

### Part 4 — robots.txt (`g0ld}`)

Checking `robots.txt` exposes a disallowed path:

```
User-agent: *
Disallow: /gold-coffer
```

Visiting `/gold-coffer` returns `g0ld}`.

### Putting it together

```
tjctf + {s1lv3r + _and_ + g0ld} = tjctf{s1lv3r_and_g0ld}
```

## Key Takeaways

- Always check `robots.txt` for hidden paths.
- Inspect HTML source for hidden elements.
- Intercept cookies set by the server.
- Follow redirects and examine all responses.
