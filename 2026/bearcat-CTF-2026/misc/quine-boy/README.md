# CTF Writeup

**Challenge Name:** Quine Boy  
**Event:** Bearcat CTF 2026  
**Category:** Misc (Code execution & flag leak)

> Feed a quine that prints itself when the checker runs as user `quine`, but reveals the flag when the same payload executes under the service’s real account.

---

## 1) Overview

The service prompts for a quine; it writes your submission to a temp file, runs it as `sudo -u quine python`, and checks that the program echoed itself exactly. If the check passes, the service prints `That will do just fine.` and immediately `exec()`s your code in the current (non-`quine`) context. The flag resides in `flag.txt`, so the only feasible solution is a payload whose behavior changes once `os.getuid()` differs.

## 2) Checker analysis

- `is_quine()` writes submitted code to `/tmp/<uuid>.py`, runs it as `quine`, and compares the stdout to the original source. Any stderr or mismatch causes rejection.  
- After verification, the service executes the same code as the challenge process owner, which is not `quine`, so the payload sees a different UID on the second execution path.  
- A well-designed quine can include a conditional that behaves like a true quine under `quine`’s UID but prints `flag.txt` when it’s run elsewhere.

## 3) Dual-behavior quine design

The payload uses a format string trick: it stores its own source and prints `s % s` when `os.getuid() == pwd.getpwnam('quine').pw_uid`, ensuring the checker sees the exact string. Otherwise, it opens `flag.txt` and prints its contents. This satisfies the deterministic behavior required for quine verification while leaking the flag when the service executes the code for real.

## 4) Exploit workflow

1. Build the payload: combine the format string with the conditional UID check so the script is both self-printing and flag-leaking.  
2. Connect to `chal.bearcatctf.io:31806` and wait for the prompt `Give me a quine`.  
3. Send the crafted quine; the checker verifies it under `quine`, then executes it under its real account, which reads `flag.txt` and prints `BCCTF{...}`.  
4. Capture the response and extract the flag via regex.

## 5) Execution

```bash
python quine-boy/solution.py
```

- The script wraps the payload in a `pwn` remote connection, sends it when prompted, and prints all received output.  
- It then searches the reply for `BCCTF{...}` and prints the flag if found.  
- Because the challenge is live-only, the full exploit succeeds only when the solver can reach `chal.bearcatctf.io:31806`.

## 6) Flag

```
BCCTF{1t5_mY_t1m3_t0_sh1n3}
```

## 7) Lessons learned

1. Code execution challenges often depend on multiple execution contexts—make your payload aware of which account is running it.  
2. A quine can be reused for stealthy indicator checks if it branches on UID or other process metadata.  
3. Always automate network interaction so you can capture the flag string once the server responds (for example, use `pwnlib` to regex-match `BCCTF{...}`).
