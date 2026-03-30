# The Hawkins Breach Writeup

Challenge Name: The Hawkins Breach  
Platform: UpSide CTF 2026  
Category: Web 

## 1) Goal (What was the task?)
The objective was to interact with a Hawkins Laboratory web portal that accepted XML Subject Reports and find a way to abuse the backend XML parser. Success meant manipulating the XML processing to disclose sensitive data and recover the flag in the `CTF{...}` format.

## 2) Key Clues (What mattered?)
- The challenge description explicitly mentioned `upload XML Subject Reports`
- It also said the XML parser was `outdated and improperly configured`
- The target endpoint was a web portal at `http://140.245.25.63:8001`
- The main page posted raw XML directly to `/upload`
- The server reflected parsed XML data back into the page, which made file disclosure very easy to confirm

## 3) Plan (Your first logical approach)
- Load the portal and inspect how the XML upload feature worked.
- Submit a normal XML report first to understand the expected response format.
- Test for XXE by defining an external entity that reads a local file.
- If file reads worked, use them to retrieve a high-value file that might contain the flag.

## 4) Steps (Clean execution)
1. I opened the site and inspected the form.
   Result: The page contained a textarea prefilled with XML and submitted it to `/upload`.
   Decision: This strongly suggested server-side XML parsing and a likely XXE target.

2. I submitted the default XML payload unchanged.
   Result: The response displayed `PROCESSING SUBJECT: 011` and `STATUS: Missing`, confirming that parsed element values were reflected back into the page.
   Decision: Since reflected XML content was visible, XXE output would likely appear directly in the response.

3. I tested a small XXE payload using an external entity pointing to `file:///etc/hostname`.
   Result: The hostname content was successfully injected into the rendered output.
   Decision: This confirmed classic XXE with local file read was enabled.

4. I switched to a more useful target file: `file:///etc/passwd`.
   Result: The server returned the full `/etc/passwd` contents in the `STATUS` field.
   Decision: Search the returned file for unusual usernames, comments, or embedded flag text.

5. I reviewed the reflected `/etc/passwd` output.
   Result: The `techtrix` account entry contained the flag in the comment/GECOS field: `CTF{fr13nds_d0nT_l13}`.
   Decision: Extract and verify the flag.

## 5) Solution Summary (What worked and why?)
The vulnerable behavior was a classic XML External Entity issue. The backend parser accepted a custom `DOCTYPE` and resolved external entities from local files. Because the application reflected parsed XML text back into the HTML response, it acted like a built-in exfiltration channel. Reading `/etc/passwd` was enough to reveal the flag directly from one of the user entries.

## 6) Flag
`CTF{fr13nds_d0nT_l13}`

## 7) Lessons Learned (make it reusable)
- When a challenge mentions XML and outdated parsing, test XXE early.
- Always send one normal request first so you know exactly where parsed values appear in the response.
- Start with a small file like `/etc/hostname` to confirm XXE safely before moving to bigger files.
- `/etc/passwd` is often a strong first target because challenge authors sometimes hide flags in user records or comments.

## 8) Personal Cheat Sheet (optional, but very useful)
- `curl -i http://host:port/` -> inspect the form and endpoints
- `curl -X POST --data-urlencode 'xml_data=...' http://host:port/upload` -> submit raw XML payloads
- XXE test payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE subject [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<subject>
  <name>&xxe;</name>
  <status>test</status>
</subject>
```

- Final payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE subject [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<subject>
  <name>011</name>
  <status>&xxe;</status>
</subject>
```

- Pattern: if XML element content is reflected in the response, XXE file contents may be visible immediately without needing an out-of-band channel
