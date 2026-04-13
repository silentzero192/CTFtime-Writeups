# Sanity 1 - Writeup

## Challenge

**Name:** `Sanity 1`  
**Description:** `Its Time to be sane. I wish I could give the flag, but I can't. Try searching this site. xd :>`  
**URL:** `https://kashictf.iitbhucybersec.in/flag`

## TL;DR

The challenge splits the flag across two places:

- `/flag` hints to check a robot
- `/robots.txt` gives the first half of the flag
- the homepage source contains an HTML comment with the second half

## Recon

Opening the page at `/flag` showed:

```text
This page may have the flag, try asking a robot!
```

That strongly hints at `robots.txt`.

Fetching:

```bash
curl -L -sS https://kashictf.iitbhucybersec.in/robots.txt
```

gave:

```text
User-agent: *
Disallow: /admin
kashiCTF{50_you_did
```

So we already have the start of the flag:

```text
kashiCTF{50_you_did
```

The `/admin` path only redirected to the login page, so the remaining hint in the description, `Try searching this site`, mattered next.

## Searching the Site

Searching the homepage source revealed a hidden HTML comment:

```html
<!--- _endup_ge77ing_the_flag_hehe} --->
```

That completed the fragment from `robots.txt`.

## Flag

```text
kashiCTF{50_you_did_endup_ge77ing_the_flag_hehe}
```

## Takeaway

This was a classic sanity challenge built around:

- checking `robots.txt`
- reading raw page source instead of only rendered content

