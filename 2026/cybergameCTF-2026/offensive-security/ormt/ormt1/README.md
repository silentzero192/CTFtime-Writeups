# ORMT - Web Chall Writeup

**Challenge Name:** `ormt`  
**Platform:** `CyberGame CTF 2026`  
**Category:** `Web`  
## 1) Goal (What was the task?)

The objective was to gain access to the `/admin` area of the bookstore app and retrieve the flag.  
Success condition was getting a valid admin response containing a flag in the format `SK-CERT{...}`.

## 2) Key Clues (What mattered?)
- `book_lookup` accepts arbitrary POST keys and values, then builds Django ORM filters dynamically.
- `clean()` in `views.py` tries to sanitize `__` in field names, but has a recursion-depth edge case.
- `admin` endpoint uses HTTP Basic Auth against `SiteUser` table (`username`, `password`, `role`).
- `0002_seed_data.py` shows an `Admin` user exists with a random 32-char alphanumeric password.
- Django model relationships allow deep traversal:
  - `Book -> Review -> SiteUser -> Review -> Book` (cyclic path).

## 3) Plan (Your first logical approach)
- Read `views.py` first to find risky input handling in `book_lookup`.
- Validate whether the `clean()` logic can be bypassed to inject raw ORM lookup keys.
- Build a valid long ORM traversal (not just long text) so Django accepts the filter.
- Use a boolean oracle (`result exists / no result`) to brute-force admin password prefix.

## 4) Steps (Clean execution)
1. **Action:** Reviewed source files (`views.py`, `models.py`, migrations).  
   **Result:** Found dynamic `Book.objects.filter(**filters)` with user-controlled keys.  
   **Decision:** Focus on ORM injection through POST parameter names.

2. **Action:** Analyzed `clean(filter, depth=0)` behavior.  
   **Result:** If input has enough `__`, recursion reaches depth 25 and raises `RecursionError`; code falls back to original raw key.  
   **Decision:** Craft keys with at least 25 `__` separators.

3. **Action:** Tested a valid cyclic lookup path repeatedly:
   `reviews__by_user__review__for_book` (looped), then appended target fields.  
   **Result:** ORM accepted long raw keys; filter became controllable.
   **Decision:** Build two injected keys:
   - role check key ending in `...__reviews__by_user__role`
   - password prefix key ending in `...__reviews__by_user__password__startswith`

4. **Action:** Used boolean oracle on `/book_lookup`: if at least one `book_card` appears, condition is true.  
   **Result:** `role=admin` returned results, confirming oracle.
   **Decision:** Brute-force password one character at a time using `password__startswith`.

5. **Action:** Recovered admin password and authenticated to `/admin` with Basic Auth (`Admin:<recovered_password>`).  
   **Result:** Received HTTP 200 with flag text.
   **Decision:** Extract and report flag.

## 5) Solution Summary (What worked and why?)
The core vulnerability was unsafe dynamic ORM filtering combined with flawed key sanitization.  
By forcing `clean()` to fail at recursion depth and supplying a syntactically valid deep relation path, raw Django lookups were injected.  
That enabled a blind boolean oracle on admin user attributes, which was used to brute-force the admin password via `startswith`.  
With valid credentials, `/admin` returned the flag.

## 6) Flag
`SK-CERT{0rm_r3l4t10n_tr4v3rs4l_g0t_y0u}`

## 7) Lessons Learned (make it reusable)
- Never pass user-controlled keys directly into ORM `filter(**kwargs)`.
- Sanitizing with simple string replacement is fragile; use strict allowlists.
- Deep model traversal can become an unintended attack surface in Django lookups.
- For blind web exploitation, a stable true/false response pattern is enough to extract secrets.

## 8) Personal Cheat Sheet (optional, but very useful)
- `Recursion edge-case` -> check sanitizer failure paths and exception fallbacks.
- `password__startswith` -> useful for incremental blind extraction in ORM injection.
- `Boolean oracle` -> count presence/absence of known UI elements (`book_card`) to detect truth.
- `Web checklist` -> always inspect source, migrations, and auth logic together.
