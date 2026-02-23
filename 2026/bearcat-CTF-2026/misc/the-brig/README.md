# CTF Writeup 

**Challenge Name:** The Brig  
**Platform:** Bearcat CTF  
**Category:** Misc (Python jail / eval abuse)  

## 1) Goal (What was the task?)
The service gives two prompts and heavily restricts input symbols.  
Success means escaping the restriction and reading `/flag.txt`, with output in `BCCTF{...}` format.

## 2) Key Clues (What mattered?)
- Prompt says we can only choose **two symbols**.
- First input is exactly length 2 and becomes allowed charset for second input.
- Core code logic:
  - `ok_chars = set(inp)`
  - `if not set(inp) <= ok_chars: ...`
  - `print(eval(long_to_bytes(eval(inp))))`
- Second payload length must be `< 2**12` (4096 chars).
- Flag path is explicitly given: `/flag.txt`.

## 3) Plan (Your first logical approach)
- Read source and understand the data flow from both user inputs into nested `eval(...)`.
- Pick two symbols that still allow arithmetic expression building (`1` and `-`).
- Build a numeric expression (using only `1` and `-`) that evaluates to the integer form of `b"eval(input())"`.
- Use that first-stage execution to get a normal unrestricted input, then send `open('/flag.txt').read()`.

## 4) Steps (Clean execution)
1. Action: Inspect `brig.py` and identify nested `eval(long_to_bytes(eval(inp)))`.  
   Result: Confirmed arbitrary code execution is possible if we can craft a valid integer under charset/length limits.  
   Decision: Use staged payload strategy.

2. Action: Send `1-` as first input (allowed symbols).  
   Result: Second input may only contain `1` and `-`.  
   Decision: Encode a useful integer expression with only these chars.

3. Action: Generate an arithmetic expression with only `1` and `-` that equals `int.from_bytes(b"eval(input())", "big")`.  
   Result: Expression length is valid (<4096), and evaluates to the target integer.  
   Decision: Use it as second input so server executes `eval(input())`.

4. Action: Immediately send `open('/flag.txt').read()` as next line.  
   Result: Server prints the flag.  
   Decision: Automate in `solve.py` for one-shot solve.

## 5) Solution Summary (What worked and why?)
The challenge is a Python jail with a two-symbol whitelist, but it still performs a dangerous nested eval chain.  
By choosing `1` and `-`, we can still form large integers via arithmetic-only expressions. Converting `b"eval(input())"` into an integer lets us pass a restricted second input that decodes into executable Python. That creates an unrestricted third input stage, where reading `/flag.txt` directly returns the flag.

## 6) Flag
`BCCTF{1--1--1--1--111--111--1111_e1893d6cdf}`

## 7) Lessons Learned (make it reusable)
- Never trust character whitelists alone when `eval` is still reachable.
- Staged payloads are powerful in pyjails: restricted stage -> unrestricted stage.
- Integer-to-bytes tricks (`int.from_bytes` / `long_to_bytes`) are common jail bypass patterns.
- Always check whether post-decode content is evaluated or executed again.

## 8) Personal Cheat Sheet (optional, but very useful)
- `eval(long_to_bytes(eval(inp)))` -> evaluate number, decode to bytes, evaluate again.
- `1-` charset trick -> arithmetic-only integer construction in symbol-limited jails.
- `int.from_bytes(b"PAYLOAD", "big")` -> turn code into a numeric target.
- Final read primitive: `open('/flag.txt').read()`.

Solver script: `solve.py`  
Run: `python3 solve.py`
