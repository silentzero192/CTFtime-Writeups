# POEM - Writeup

## Challenge Info

**Name:** `POEM`  
**Description:** `I like to have my poems saved on CTFd instances like this. But the admin does like it, so I hid the secret in my poem.`  
**URL:** `https://kashictf.iitbhucybersec.in/poem`

## TL;DR

The flag is hidden in trailing whitespace inside the poem block. The spaces and tabs at the ends of lines encode a `SNOW`-style whitespace payload.

## First Observation

The page renders a Robert Frost poem inside a `<pre><code>` block. Looking at the raw HTML instead of the rendered page shows a suspicious amount of trailing whitespace after every line.

For example:

```bash
curl -L -sS https://kashictf.iitbhucybersec.in/poem | \
sed -n '/<pre><code/,/<\/code><\/pre>/p' | cat -A
```

This makes the tabs visible as `^I`, which immediately suggests whitespace steganography.

## Extraction

The hidden data is stored in the poem's end-of-line spaces and tabs. After extracting the exact code block, I decoded the whitespace stream into bits and then into bytes.

A minimal decoder looked like this:

```python
import re
from pathlib import Path

html = Path("/tmp/poem.html").read_text()
block = re.search(r'<pre><code class="language-txt">(.*?)</code></pre>', html, re.S).group(1)

bits = []
started = False

for line in block.splitlines():
    m = re.search(r'([ \t]+)$', line)
    if not m:
        continue
    ws = m.group(1)
    i = 0
    if not started:
        if ws and ws[0] == '\t':
            started = True
            i = 1
        else:
            continue
    spaces = 0
    for ch in ws[i:]:
        if ch == ' ':
            spaces += 1
        else:
            bits.extend([(spaces >> 0) & 1, (spaces >> 1) & 1, (spaces >> 2) & 1])
            spaces = 0
    if spaces:
        bits.extend([(spaces >> 0) & 1, (spaces >> 1) & 1, (spaces >> 2) & 1])

out = bytearray()
cur = 0

for idx, bit in enumerate(bits, 1):
    cur = (cur << 1) | bit
    if idx % 8 == 0:
        out.append(cur)
        cur = 0

print(out.decode())
```

## Flag

```text
kashiCTF{1_like_poems_but_1_lik3_u_more<3}
```

## Takeaway

Whenever a text challenge uses `<pre>` blocks and the content looks normal, it is worth checking:

- trailing spaces
- tabs mixed with spaces
- raw HTML instead of the browser view

