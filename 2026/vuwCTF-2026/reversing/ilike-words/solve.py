#!/usr/bin/env python3
"""
solver for the "ilike-words" reversing challenge (VuwCTF)

Reverse engineered program logic (see WRITEUP.md for the full details):

  1. func_1b4c()  -> "random" seed via a Kaprekar routine.
       seed = rand()%9000+1000, then sort its 4 digits asc/desc,
       subtract, repeat until stable.  Any 4-digit input collapses
       to Kaprekar's constant 6174, so the seed is ALWAYS 6174.

  2. func_1a31()  -> XOR-decrypts an obfuscated rodata blob with that
       seed to recover the curl URL format string:
           https://www.nytimes.com/svc/wordle/v2/%s.json

  3. func_19a4()  -> prints today's date as "%d-%02d-%02d"
       using (tm_year+1900, tm_mon+1, tm_mday) -> e.g. "2026-08-01".

  4. The binary fetches that URL (NYT Wordle API) and func_17b2()
     extracts the key: strstr(resp, "\":\"") + 3, first 5 bytes
     -> the Wordle solution word for today (e.g. "slush").

  5. The printed flag is "VuwCTF{do_you_like_%s_as_much_as_i?}" where
     %s is 6 bytes copied from the URL buffer (offset 28) -> "wordle".
"""

import time
import urllib.request

OBS = b"vkjmo!54kji1pdhrw~o3}ps2omy4krl{rx3m(49n0umrr"


def kaprekar_seed(r: int) -> int:
    """func_1b4c: collapse r to Kaprekar's constant (always 6174)."""
    while True:
        digits = [r // 1000 % 10, r // 100 % 10, r // 10 % 10, r % 10]
        prev = r
        asc = int("".join(map(str, sorted(digits)))) or 0
        desc = int("".join(map(str, sorted(digits, reverse=True))))
        r = desc - asc
        if r == prev:
            return r


def decrypt_url(seed: int) -> bytes:
    """func_1a31: walk the blob, XOR each byte with the walking seed."""
    out = bytearray(OBS)
    counter = 3
    flag = 1
    i = 0
    while i < len(out) and out[i] != 0:
        out[i] ^= seed & 0xFF
        counter += 1
        if counter % 5 == 0:
            if flag:
                seed -= 1
                flag = 0
            else:
                seed += 1
                flag = 1
        else:
            if flag:
                seed += 1
            else:
                seed -= 1
        i += 1
    return bytes(out[:i])


def main() -> None:
    seed = 6174
    fmt = decrypt_url(seed)
    print(f"[*] seed from Kaprekar routine : {seed}")

    date = time.strftime("%Y-%m-%d")
    url = (fmt % date.encode()).decode()
    print(f"[*] decrypted URL format       : {fmt.decode()}")
    print(f"[*] date                       : {date}")
    print(f"[*] fetched URL                : {url}")

    with urllib.request.urlopen(url) as resp:
        body = resp.read().decode()
    print(f"[*] API response               : {body}")

    # func_17b2: strstr(resp, "\":\"") -> the char after is the solution word
    key = body.split('":"', 1)[1][:5]
    print(f"[*] extracted key (solution)   : {key!r}")

    # flag %s: 6 bytes of the URL buffer at offset 28 -> "wordle"
    word = url[28:34]
    flag = f"VuwCTF{{do_you_like_{word}_as_much_as_i?}}"
    print()
    print(f"[+] KEY  : {key}")
    print(f"[+] FLAG : {flag}")


if __name__ == "__main__":
    main()
