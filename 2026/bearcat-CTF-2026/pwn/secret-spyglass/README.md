Challenge Name: Secret Spyglass
Platform: Bearcat CTF 2026
Category: Pwn
Difficulty: Easy
Time spent: ~20 minutes

## 1) Goal (What was the task?)
The binary asks for a numeric guess and compares it against a secret random number from `/dev/urandom`.  
Success means making the program print the flag in `BCCTF{...}` format from `print_flag()`.

## 2) Key Clues (What mattered?)
- The challenge gives a remote service: `nc chal.bearcatctf.io 20011`
- In source, user input is passed directly to `printf(input);`
- Two guesses are allowed in one run, but `secret_num` is generated only once
- `strtoul` allows input that starts with a valid number, then extra characters (format string payload still reaches `printf`)
- Prompt expects full 64-bit unsigned range (`1` to `18446744073709551615`)

## 3) Plan (Your first logical approach)
- Read `spyglass.c` first to look for memory corruption or input handling bugs.
- Focus on `printf(input)` as a format string vulnerability.
- Leak values from the stack using `%<index>$lu` until finding `secret_num`.
- Use first guess to leak, second guess to submit leaked value and pass the equality check.

## 4) Steps (Clean execution)
1. Action: Opened and reviewed `spyglass.c`.  
   Result: Found `printf(input);` in `get_guess()` and saw `main()` stores one `secret_num` for both rounds.  
   Decision: Try format string leak in round 1, then reuse leaked value in round 2.

2. Action: Tested positional format specifiers (`%1$lu`, `%2$lu`, ...).  
   Result: `%14$lu` reliably leaked the current run’s `secret_num`.  
   Decision: Build final exploit around payload `1|%14$lu|` for easy parsing.

3. Action: Wrote `exploit.py` using pwntools:
   - Send first input: `1|%14$lu|`
   - Parse leaked decimal between `|...|`
   - Send leaked value as second guess
   Result: Service replied with `Second time's the charm` and printed the flag.  
   Decision: Extract and record final flag.

## 5) Solution Summary (What worked and why?)
This challenge is a classic format string leak. The program mistakenly treats user input as a format string (`printf(input)`), so we can read stack values with `%14$lu`. The secret random number remains constant for both attempts in one process, so leaking it in attempt 1 and sending it back in attempt 2 makes `guess == secret_num` true and triggers `print_flag()`.

## 6) Flag
`BCCTF{I_spY_W1th_My_L177L3_eY3...}`

## 7) Lessons Learned (make it reusable)
- Never pass raw user input as `printf` format string.
- In pwn challenges, two-step games often allow leak-then-use strategies.
- With `strtoul`, payloads like `1|%14$lu|` are useful because they pass numeric checks but still include exploit content.
- For format strings, positional specifiers (`%n$...`) make leaks stable and scriptable.

## 8) Personal Cheat Sheet (optional, but very useful)
- `printf(user_input)` -> check for format string vuln immediately.
- `%<idx>$lu` -> leak unsigned long from stack at position `idx`.
- `1|%14$lu|` -> good payload pattern when input must start as a number.
- `pwntools remote(host, port)` -> automate leak/parse/replay quickly.
