# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

**Challenge Name:** The Mindflayer's Gambit  
**Platform:** Upside CTF 2026  
**Category:** Web  
**Difficulty:** Easy  
**Time spent:** ~25 minutes

## 1) Goal (What was the task?)
The challenge presented a chess web app where the "Mindflayer" engine was supposed to be impossible to beat normally. The goal was to recover the flag in the format `CTF{...}` by exploiting the app rather than winning a real chess game.

## 2) Key Clues (What mattered?)
- Prompt keywords: "connection ... isn't as secure as it seems"
- Hint: "The engine calculates its own 'advantage' score"
- Hint: "The flag after defeating mindflayer might not be the final flag"
- Hint: "the key might be the main villain from the series"
- Web endpoint: `http://140.245.25.63:8002/`
- WebSocket endpoint found in page source: `/ws/`
- Unusual behavior: the frontend was sending evaluation values from the browser to the server

## 3) Plan (Your first logical approach)
- Open the challenge page and inspect the HTML/JavaScript to understand how the chess game works.
- Look for anything sensitive happening client-side, especially around score/evaluation handling.
- Test the websocket directly instead of playing chess normally.
- If the service returned a fake or encrypted flag, use the challenge hints to decode it.

## 4) Steps (Clean execution)
1. **Action:** Requested the homepage and inspected the returned HTML/JavaScript.  
   **Result:** The page created a websocket connection to `/ws/` and sent messages like `eval <number>`.  
   **Decision:** This was the main trust boundary to attack because the server appeared to accept evaluation data from the client.

2. **Action:** Read the key part of the frontend logic in the page source.  
   **Result:** The code openly described the exploit path:
   - normal traffic sends `ws.send("eval " + (Math.random() * 10))`
   - a comment stated that the player could manually inject `eval -10000` to win  
   **Decision:** Instead of playing chess, directly connect to the websocket and forge the message.

3. **Action:** Connected to the websocket with `wscat`.  
   **Command:** `wscat -c ws://140.245.25.63:8002/ws/`  
   **Result:** The server accepted the connection.  
   **Decision:** Send a very negative evaluation to force the Mindflayer to resign.

4. **Action:** Sent the forged message `eval -10000`.  
   **Result:** The server responded with:  
   `The Mindflayer has resigned, but he encrypted his surrender terms!.. 59f68bb2e8289cddd92338af2be4094bdfbc3c3c00a90a1c`  
   **Decision:** Since the hint warned that this was not the final flag, treat the hex string as ciphertext.

5. **Action:** Used the series-villain hint and tested likely keys such as `Vecna` / `vecna`.  
   **Result:** Simple XOR with raw `vecna` did not produce readable text.  
   **Decision:** Try a derived key instead of the raw word.

6. **Action:** XORed the ciphertext with `sha256("vecna")`.  
   **Result:** The plaintext decoded cleanly to `CTF{mindflayer_resigned}`.  
   **Decision:** This matched the required flag format, so it was the final answer.

## 5) Solution Summary (What worked and why?)
The challenge relied on a classic client-trust mistake. Instead of calculating the engine's evaluation securely on the server, the application accepted `eval` messages directly from the browser over a websocket. By sending `eval -10000`, I tricked the server into believing the engine was completely losing, which triggered the resign path and leaked an encrypted message. The final hint pointed to the villain `vecna`, and using `sha256("vecna")` as the XOR key revealed the real flag.

## 6) Flag
`CTF{mindflayer_resigned}`

## 7) Lessons Learned (make it reusable)
- Never trust client-side values in web challenges, especially scores, roles, and game state.
- For web CTFs, always inspect the page source and JavaScript early.
- If a challenge gives story-based hints, they may point to the decryption key or key-derivation method.
- When raw XOR keys fail, try common derived forms like hashes.

## 8) Personal Cheat Sheet (optional, but very useful)
- `curl -i http://target/` -> quickly inspect HTML and headers
- `wscat -c ws://target/ws/` -> talk to websocket services directly
- Browser source / JS review -> find hidden endpoints, comments, and trust issues
- Pattern: Web -> always check whether the client is sending sensitive values the server should compute itself
- Pattern: Crypto hint -> test both the literal hint word and hashed/derived versions of it
