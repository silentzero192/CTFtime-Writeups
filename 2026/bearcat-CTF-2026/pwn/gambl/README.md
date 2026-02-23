# CTF Writeup 

**Challenge Name:** Gambl  
**Platform:** Bearcat CTF 2026  
**Category:** Pwn  
**Difficulty:** Easy  
**Time spent:** ~35 minutes

## 1) Goal (What was the task?)
The challenge asked me to find an "infinite money glitch" in a gambling simulator and buy the flag in-game.  
Success condition was reaching enough money to use option `4) Buy Flag`, then receiving a flag in format `BCCTF{...}`.

## 2) Key Clues (What mattered?)
- Prompt hint: "infinite money glitch"
- Source file: `speculative_piracy.c`
- Remote endpoint: `nc chal.bearcatctf.io 22723`
- Important logic:
  - Daily loop is supposedly limited to 15 days (`while (i <= 15)`)
  - "Bad day" rollback condition: `if ((money + investedMoney) / dayStartMoney < .75)`
  - Macro bug: `#define MAX(a,b) a > b ? a : b`
  - Investment overwrite bug in `investCrypto()` (`investedMoney = investmentAmount` every time)

## 3) Plan (Your first logical approach)
- Read the source first to understand all win/loss and loop-ending conditions.
- Find a way to bypass or reset the 15-day limit.
- Find a repeatable way to grow money each cycle.
- Automate the interaction to avoid manual menu input errors.

## 4) Steps (Clean execution)
1. **Action:** Read and map the main loop in `speculative_piracy.c`.  
   **Result:** Found that profit can come from crypto investing and that days are controlled by `i` and `day`.  
   **Decision:** Focus on the "bad day" rollback branch for loop control abuse.

2. **Action:** Analyze rollback branch and macro expansion.  
   **Result:** `MAX(0, --i)` evaluates `--i` twice (macro side effect), so `i` can be decremented unexpectedly.  
   **Decision:** Trigger this branch repeatedly to prevent normal loop exhaustion.

3. **Action:** Test multi-invest behavior in one day.  
   **Result:** First `invest(50%)` reduces `money`, then `invest(0)` overwrites `investedMoney` to `0`.  
   **Decision:** This forces `(money + investedMoney) / dayStartMoney` below `0.75`, triggering rollback while restoring money to `dayStartMoney`.

4. **Action:** Build a 2-phase cycle:
   - Good day: invest almost all money (`money - 0.01`), complete day for 1.44x-1.59x growth.
   - Bad day: `invest(50%)`, then `invest(0)`, complete day to trigger rollback and keep loop alive.  
   **Result:** Money compounds across many effective growth days without hitting a hard 15-day stop.  
   **Decision:** Automate this strategy.

5. **Action:** Write `solve.py` to parse menus and run the cycle until money > 5,000,000, then send option `4`.  
   **Result:** Script reliably retrieves the flag from the remote service.

## 5) Solution Summary (What worked and why?)
The solve combined two bugs: a macro side-effect in loop control and an investment overwrite bug. I used the overwrite bug to intentionally trigger the "bad day" rollback branch, which manipulates the day-counter logic and avoids normal game termination. Between rollback triggers, I ran profitable crypto days that compound balance quickly. Repeating this cycle builds enough money to buy the flag.

## 6) Flag
`BCCTF{1_Ju57_G0t_Macro_Pwnoed_D:}`

## 7) Lessons Learned (make it reusable)
- Unsafe C macros can create hidden double-evaluation bugs with side effects (`--i` in macro args).
- Global state overwrite bugs (`=` vs accumulate) can be chained with control-flow checks.
- In menu pwn challenges, repeated actions in one "turn" often expose state machine flaws.
- Automating interactions early saves time and reduces desync mistakes.

## 8) Personal Cheat Sheet (optional, but very useful)
- `python3 solve.py` -> run full exploit against remote challenge.
- `nc chal.bearcatctf.io 22723` -> manual interaction / quick sanity checks.
- Pattern to remember:
  - C macro with arguments that mutate state (`++`, `--`) -> check for repeated evaluation.
  - "Rollback on bad condition" logic -> see if state can be intentionally forced then reset.
  - Repeated menu option in one round -> test for overwrite vs accumulate bugs.
