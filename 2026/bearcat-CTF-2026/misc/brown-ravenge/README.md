# CTF Writeup

**Challenge Name:** Brown’s Revenge  
**Event:** Bearcat CTF 2026  
**Category:** Misc (Input reconstruction)

> The binary expects a 4107-character bit string that contains every 12-bit access code it randomly generates over 20 rounds. A De Bruijn sequence supplies all codes in one shot.

---

## 1) Overview

Each login round: the service prints `Enter the access string:` and generates a random 12-bit code. You must submit a string containing that code as a substring. After 20 correct rounds, it prints the flag from `flag.txt`. The constraints—binary alphabet, max length 4107, 20 random codes—suggest a single crafted payload should satisfy every possible code.

## 2) Key observations

- Every round’s code is a 12-bit binary string, so there are only 2¹² = 4096 possibilities.  
- The service only rejects if the submitted string is longer than 4107 characters or doesn’t contain the generated code.  
- A binary De Bruijn sequence of order 12 is a cyclic string in which every 12-bit pattern appears exactly once; extending it by the first 11 bits yields a linear string of length 4096 + 11 = 4107 that contains every possible code.

## 3) Payload construction

1. Generate B(2, 12) via the recursive De Bruijn algorithm (`de_bruijn_binary(12)` returns the minimal cycle).  
2. Append the first `order - 1` bits to the cycle to linearize it; this ensures the wrap-around codes appear in a straight string.  
3. Verify the payload length is 4107 exactly, matching the service’s limit.  
4. Send the payload once per round; because every 12-bit code exists within the string, the service accepts all 20 submissions and releases the flag.

## 4) Execution

```bash
python brown-ravenge/solve.py
```

- The script builds the payload, connects to `chal.bearcatctf.io:19679`, waits for each prompt, and replies with the De Bruijn string.  
- After 20 rounds, it drains the remaining output, prints the flag block, and extracts `BCCTF{...}` using a regex.  
- Network access to the challenge host is required; the offline payload generation and length check can still be verified locally.

## 5) Flag

```
BCCTF{i_5pe11ed_de_brujin_wr0ng_7689472}
```

## 6) Lessons learned

1. De Bruijn sequences are perfect for “every code” problems—they let you cover all substrings of a fixed length within the smallest possible string.  
2. Always confirm the service’s length limits to avoid rejection; here 4107 matches `2^{12} + 11`.  
3. Automating the interaction (e.g., with `pwnlib`) keeps the exploit repeatable and lets you immediately extract the flag once the server responds.
