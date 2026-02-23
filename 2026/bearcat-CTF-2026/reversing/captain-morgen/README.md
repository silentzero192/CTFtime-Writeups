# CTF Writeup 

**Challenge Name:** Captain Morgan  
**Platform:** Bearcat CTF 2026  
**Category:** Reversing  
**Difficulty:** Medium  
**Time spent:** 35 minutes

## 1) Goal (What was the task?)
The challenge gave an obfuscated Python file and asked for the correct input that unlocks the tomb.  
Success meant producing a valid flag in the format `BCCTF{...}` that makes the script print `correct`.

## 2) Key Clues (What mattered?)
- Only one file existed: `chall.py`
- The script was heavily obfuscated with thousands of chained assignments
- The input format check was visible:
  - `agu.startswith("BCCTF{")`
  - `agu[-1] == "}"`
- The final line was critical: `print("in"*bfu+"correct")`
  - If `bfu == 0`, output is `correct`
  - If `bfu == 1`, output is `incorrect`

## 3) Plan (Your first logical approach)
- Inspect the script for the final decision variable (found `bfu`).
- Avoid manual tracing of 2000+ assignments and instead isolate only expressions that affect `bfu`.
- Convert the bitwise logic into SAT constraints and solve for the unknown payload value.
- Rebuild the inner flag string from the solved integer and verify by running `chall.py`.

## 4) Steps (Clean execution)
1. **Action:** Listed files and confirmed the challenge only contains `chall.py`.  
   **Result:** Single obfuscated Python script.  
   **Decision:** Static reverse was the right path.

2. **Action:** Read the script and focused on the final output expression.  
   **Result:** Found `print("in"*bfu+"correct")`, so solving required forcing `bfu = 0`.  
   **Decision:** Work backward from `bfu` rather than deobfuscating everything.

3. **Action:** Parsed the file with Python `ast` and built a dependency slice for `bfu`.  
   **Result:** Reduced the problem to only the variables that influence `bfu`.  
   **Decision:** Model the slice as bit-level boolean equations.

4. **Action:** Encoded `&`, `|`, `^`, and `>>` operations into CNF and solved with `pycosat`.  
   **Result:** Recovered the integer corresponding to `agu[6:-1]` (`ari` in code).  
   **Decision:** Convert that integer back to bytes.

5. **Action:** Converted the solved integer to ASCII bytes.  
   **Result:** Recovered inner text: `Y00_hO_Ho_anD_4_B07Tl3_oF_rUm`.  
   **Decision:** Wrap it with format prefix/suffix and verify.

6. **Action:** Tested `BCCTF{Y00_hO_Ho_anD_4_B07Tl3_oF_rUm}` against `chall.py`.  
   **Result:** Program printed `correct`.  
   **Decision:** Final flag confirmed.

## 5) Solution Summary (What worked and why?)
The core pattern was a giant obfuscated bitwise circuit that ultimately reduced to one control bit (`bfu`) deciding `correct` vs `incorrect`. Instead of manual tracing, the reliable method was to isolate dependencies of `bfu`, encode the operations as SAT constraints, and solve for the unknown input bits (`ari`, derived from the flag body). That directly revealed the correct flag payload.

## 6) Flag
`BCCTF{Y00_hO_Ho_anD_4_B07Tl3_oF_rUm}`

## 7) Lessons Learned (make it reusable)
- In obfuscated reversing challenges, first locate the final branch/output condition.
- Dependency slicing saves huge time compared to reading the full obfuscated chain.
- Bitwise-heavy logic is often best solved as SAT/SMT constraints.
- Always validate recovered input by running the original binary/script.

## 8) Personal Cheat Sheet (optional, but very useful)
- `rg --files` -> quickly list challenge files
- `python + ast` -> parse obfuscated Python and extract dependency graph
- SAT (`pycosat`) -> solve boolean/bit constraints from bitwise expressions
- Pattern: In Python obfuscation, search for final `print`/comparison first, then backtrack only required variables
