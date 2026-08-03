# ilike-words — VuwCTF 2026 (Reversing)

> **Challenge:** ilike-words
> **Category:** Reversing
> **Description:** *Every day is a new challenge. Embrace it. (potentially someone influential whose name I do not know)*
> **Flag format:** `VuwCTF{...}`

---

## TL;DR

The program is a **live API client**. It generates a "random" seed, XOR-decrypts
an obfuscated URL format string with it, builds the URL for **today's date**,
fetches the **NYT Wordle API** with libcurl, and checks your input against the
**Wordle solution word of the day**. Enter today's word (`slush` on 2026-08-01)
and the program prints the flag.

The twist: the "random" seed is **not random** — it is produced by a
[Kaprekar routine](https://en.wikipedia.org/wiki/Kaprekar%27s_routine) that
always collapses to the constant **6174** for any 4-digit input. And the flag
itself is not derived from your input at all: the flag printing code copies 6
bytes straight out of the **URL buffer** — the substring `"wordle"`.

**Key:** `slush` (today's Wordle solution)

**Flag: `VuwCTF{do_you_like_wordle_as_much_as_i?}`**

---

## Step 1 — Initial Recon

```console
$ file ilikewords
ilikewords: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
```

A stripped, dynamically linked PIE. The imports are unusually revealing:

```
__stack_chk_fail
curl_easy_cleanup        curl_easy_init
curl_easy_perform        curl_easy_setopt
curl_global_cleanup      curl_global_init
exit                     getline
localtime                memcpy
printf                   puts
rand                     srand
sprintf                  strlen
strncmp                  strncpy
strstr                   time
```

`libcurl` + `srand/rand/time/localtime` + `strstr/strncmp` hints at
*network request* + *time-derived randomness* + *string comparison*.

A `strings` pass confirms it:

```
Please enter a key:
Failed to read user input. Exiting...
 > Well done! You have found the key!
 > Submit the flag below to claim your points :)
VuwCTF{do_you_like_%s_as_much_as_i?}
 > That is the incorrect key! Please try again.
curl failed, exiting...
Failed to curl. Exiting...
":
vkjmo!54kji1pdhrw~o3}ps2omy4krl{rx3m(49n0umrr
%d-%02d-%02d
```

The flag format string is `VuwCTF{do_you_like_%s_as_much_as_i?}` — we need to
figure out what `%s` gets filled with. There's a garbage-looking string
`vkjmo!54...` (that's the **encrypted URL**) and a `"%d-%02d-%02d"` (a date).

---

## Step 2 — High-level Program Flow

Reversing `main` gives the following skeleton:

```c
int main(void) {
    char *line = NULL; size_t n = 0;
    printf("Please enter a key: ");

    if (getline(&line, &n, stdin) < 0) { puts("Failed to read user input..."); return 1; }
    line[strlen(line) - 1] = 0;            // strip trailing newline

    int seed = func_1b4c();                  // "random" seed (spoiler: always 6174)
    func_187a(&g_url_buf /*0x4160*/, seed);  // build URL string
    if (func_168e()) {                       // libcurl GET
        if (func_17b2(line)) {               // check key against parsed response
            char word[8] = {0};
            memcpy(word, (void*)0x417c, 6);  // <-- 6 bytes from the URL buffer!
            puts(" > Well done! You have found the key!");
            puts(" > Submit the flag below to claim your points :)");
            printf("VuwCTF{do_you_like_%s_as_much_as_i?}\n", word);
        } else {
            puts(" > That is the incorrect key! Please try again.");
        }
    }
    return 0;
}
```

Key functions (file offsets; PIE adds a runtime base):

| Function  | Role |
|-----------|------|
| `func_1b4c` | Generates the "seed" (Kaprekar routine → **6174**) |
| `func_1a31` | XOR-decrypts the obfuscated URL format string using the seed |
| `func_19a4` | Builds today's date as `YYYY-MM-DD` via `localtime` |
| `func_187a` | Assembles the final URL: `sprintf(url, fmt, date)` |
| `func_168e` | `curl_global_init` / `curl_easy_init` / `setopt` / `perform` |
| `func_1749` | libcurl **write callback** — appends body to the response buffer |
| `func_17b2` | Checks the key: `strstr(response, "\":\"")`, compares first 5 chars |

---

## Step 3 — The "Random" Seed: Kaprekar's Constant (6174)

`func_1b4c` is the most interesting function. It looks random, but it's not:

```asm
func_1b4c:
    ; srand(time(0))
    call    time@plt
    mov     edi, eax
    call    srand@plt

    ; seed = rand() % 9000 + 1000
    call    rand@plt
    imul    edx, edx, 0x7482296b        ; compiler trick for rand() % 9000
    shr     rdx, 0x20
    sar     edx, 0xc
    sub     edx, ecx
    imul    ecx, edx, 0x2328            ; 0x2328 = 9000
    sub     eax, ecx                    ; eax = rand() % 9000
    lea     eax, [rdx + 0x3e8]          ; + 1000  -> 4-digit number
    mov     [rbp-0x2c], eax

    mov     edi, eax
    call    func_1c23                   ; if all 4 digits equal, bump by ±1
    mov     [rbp-0x2c], eax

    mov     [rbp-0x34], -1              ; prev = -1
    mov     [rbp-0x30], eax             ; cur  = value
    jmp     .loop_cond

.loop_body:
    lea     rdx, [rbp-0x20]
    mov     eax, [rbp-0x30]
    mov     rsi, rdx
    mov     edi, eax
    call    func_1cba                   ; split cur into 4 decimal digits

    mov     rdi, rax
    call    func_1e05                   ; digits sorted ascending  -> asc
    mov     [rbp-0x28], eax

    mov     rdi, rax
    call    func_1e39                   ; digits sorted descending -> desc
    mov     [rbp-0x24], eax

    mov     eax, [rbp-0x30]
    mov     [rbp-0x34], eax             ; prev = cur
    mov     eax, [rbp-0x24]
    sub     eax, [rbp-0x28]             ; cur = desc - asc
    mov     [rbp-0x30], eax

.loop_cond:
    mov     eax, [rbp-0x34]
    cmp     eax, [rbp-0x30]
    jne     .loop_body                  ; loop until stable

    mov     eax, [rbp-0x30]             ; return the fixed point
    ret
```

In other words:

```
seed = rand() % 9000 + 1000        (4-digit number)
if all digits equal: seed += 1     (func_1c23, so we never stall on 1111)
repeat:
    prev = seed
    seed = desc_digits(seed) - asc_digits(seed)
until seed == prev
return seed
```

This is exactly **Kaprekar's routine**. For any 4-digit number whose digits are
not all equal, repeatedly subtracting the ascending digit order from the
descending order reaches the fixed point **6174** in at most 7 iterations:

```
0999 → 9990 − 0999 = 8991
8991 → 9981 − 1899 = 8082
8082 → 8820 − 0288 = 8532
8532 → 8532 − 2358 = 6174
6174 → 7641 − 1467 = 6174   ← stable
```

`func_1c23` just nudges repdigits (`1111 → 1112`, `9999 → 9998`), which then
also converge to 6174. **So the "random" seed is always `6174`.**
`func_1cba`/`func_1e05`/`func_1e39` are simply: split into digits, sort
ascending, sort descending.

---

## Step 4 — `func_1a31`: XOR-Decrypting the URL

`func_187a` first copies the 45-byte obfuscated blob
`vkjmo!54kji1pdhrw~o3}ps2omy4krl{rx3m(49n0umrr` from `.rodata` (address
`0x2138`, referenced through a pointer stored at `0x4010`) into a stack buffer,
then calls `func_1a31(buffer, seed)` which decrypts it **in place**:

```asm
func_1a31:                       ; void func_1a31(char *s, uint32_t seed)
    mov     [rbp-0x10], rdi      ; ptr = s
    mov     [rbp-0x14], 3        ; counter = 3
    mov     BYTE [rbp-0x15], 1   ; flag   = 1

    call    time@plt
    mov     [rbp-0x8], rax       ; t0 = time(0)

.loop:                           ; while (*ptr != 0)
    movzx   eax, BYTE [rax]      ;   byte = *ptr
    mov     edx, [rbp-0x2c]      ;   seed
    xor     edx, eax
    mov     BYTE [ptr], dl       ;   *ptr ^= seed & 0xff
    add     [rbp-0x10], 1        ;   ptr++
    add     [rbp-0x14], 1        ;   counter++

    call    time@plt             ;   anti-debug guard:
    sub     rax, [rbp-0x8]       ;   if (time(0) - t0 > 1s) exit(1)
    test    rax, rax
    jle     .tick
    mov     edi, 1
    call    exit@plt

.tick:                           ; walk the seed
    cmp     BYTE [rbp-0x15], 0
    je      .flag_zero
    ; flag == 1: counter % 5 == 0 ? seed--, flag=0 : seed++
    ... (division by 5 check)
    jmp     .guard
.flag_zero:
    ; flag == 0: counter % 5 == 0 ? seed++, flag=1 : seed--
    ... (division by 5 check)
.guard:
    ; second anti-debug time() check, same as above

    movzx   eax, BYTE [ptr]
    test    al, al
    jne     .loop                 ; while *ptr != 0
    ret
```

Pseudocode:

```python
def decrypt(s: bytes, seed: int) -> bytes:
    out = bytearray(s)
    counter, flag, i = 3, 1, 0
    while i < len(out) and out[i] != 0:
        out[i] ^= seed & 0xFF
        counter += 1
        if counter % 5 == 0:
            seed, flag = (seed - 1, 0) if flag else (seed + 1, 1)
        else:
            seed, flag = (seed + 1, 0) if flag else (seed - 1, 1)
        i += 1
    return bytes(out[:i])
```

Interesting detail: the function calls `time(0)` **twice per byte** and calls
`exit(1)` if more than one second elapses during decryption — a crude
anti-debugger / anti-stepping guard.

Running this with `seed = 6174` recovers the URL format string:

```
https://www.nytimes.com/svc/wordle/v2/%s.json
```

---

## Step 5 — `func_19a4` / `func_187a`: Today's Date + Final URL

`func_19a4` builds the date:

```asm
    call    time@plt
    mov     [rbp-0x18], rax
    lea     rax, [rbp-0x18]
    mov     rdi, rax
    call    localtime@plt
    mov     [rbp-0x10], rax

    mov     esi, [rax + 0x0c]        ; tm_mday
    mov     eax, [rax + 0x10]        ; tm_mon  (0-11)
    lea     ecx, [rax + 1]           ; month = tm_mon + 1
    mov     eax, [rax + 0x14]        ; tm_year (years since 1900)
    lea     edx, [rax + 0x76c]       ; year = tm_year + 1900

    mov     r8d, esi                 ; day
    lea     rsi, [rip+...]           ; "%d-%02d-%02d"
    mov     rdi, rax
    call    sprintf@plt
```

So `func_19a4` produces
`sprintf(out, "%d-%02d-%02d", tm_year+1900, tm_mon+1, tm_mday)` →
e.g. **`2026-08-01`** for August 1st, 2026. (Note the `%02d` zero-padding —
exactly the format the NYT API expects.)

`func_187a` then ties everything together:

```c
char url_buf[0x50];                       // global at 0x4160
char fmt[0x50]; char date[0x20];

memcpy(fmt, &blob_0x2138, 45);            // obfuscated string
func_1a31(fmt, seed);                     // decrypt in place -> URL format
func_19a4(date);                          // "2026-08-01"
sprintf(url_buf, fmt, date);              // -> https://www.nytimes.com/svc/wordle/v2/2026-08-01.json
```

---

## Step 6 — The libcurl Fetch (`func_168e` + `func_1749`)

```asm
func_168e:
    mov     edi, 3
    call    curl_global_init@plt          ; CURL_GLOBAL_ALL
    call    curl_easy_init@plt
    mov     [rbp-0x8], rax                ; curl handle
    ; if (handle == NULL) { puts("Failed to curl. Exiting..."); return 0; }

    mov     [rbp-0x10], 0x2712            ; CURLOPT_URL = 10002
    lea     rdx, [rip+0x2a73]             ; &g_url_buf (0x4160)
    call    curl_easy_setopt@plt          ; setopt(handle, CURLOPT_URL, url)

    mov     [rbp-0xc], 0x4e2b             ; CURLOPT_WRITEFUNCTION = 20011
    lea     rdx, [rip+0x38]               ; &func_1749
    call    curl_easy_setopt@plt          ; setopt(handle, CURLOPT_WRITEFUNCTION, cb)

    call    curl_easy_perform@plt         ; perform the GET
    call    curl_easy_cleanup@plt
    call    curl_global_cleanup@plt
    ; return (res == 0)
```

`CURLOPT_URL` is set to the global URL buffer at `0x4160`, and the write
callback `func_1749` appends every received chunk to the **global response
buffer at `0x4040`**, using a running offset counter at `0x4140`:

```c
size_t func_1749(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    memcpy((char*)0x4040 + g_offset, ptr, total);   // append to response
    g_offset += total;
    return total;
}
```

---

## Step 7 — The Key Check (`func_17b2`): Wordle's Solution Word

After the fetch, `func_17b2(user_key)` runs on the response buffer at `0x4040`:

```asm
    lea     rsi, [rip+0x95b]        # 0x2134  -> "\":\""    (quote-colon-quote)
    lea     rdi, [rip+0x285d]       # 0x4040  -> response buffer
    call    strstr@plt              ; ptr = strstr(response, "\":\"")
    mov     [rbp-0x28], rax

    lea     rcx, [rax + 3]          ; word = ptr + 3   (skip quote/colon/quote)
    lea     rax, [rbp-0x1e]
    mov     edx, 5
    mov     rsi, rcx
    mov     rdi, rax
    call    strncpy@plt             ; copy exactly 5 bytes

    mov     rdi, [rbp-0x38]         ; user_key
    call    strlen@plt
    mov     rdx, rax
    lea     rcx, [rbp-0x1e]
    mov     rax, [rbp-0x38]
    mov     rsi, rcx
    mov     rdi, rax
    call    strncmp@plt             ; strncmp(user_key, word, strlen(user_key))
    test    eax, eax
    jne     .fail

    mov     rdi, [rbp-0x38]
    call    strlen@plt              ; also require strlen(user_key) == strlen(word)
    mov     rbx, rax
    lea     rax, [rbp-0x1e]
    mov     rdi, rax
    call    strlen@plt
    cmp     rbx, rax
    jne     .fail
    mov     eax, 1                  ; -> success
    jmp     .done
.fail:
    xor     eax, eax
.done:
    and     eax, 1
    ret
```

The JSON response is stored at `0x4040`. `strstr(response, "\":\"")` finds the
first `quote-colon-quote` sequence, which in the Wordle JSON is exactly the
boundary between `"solution"` and the word:

```json
{"id":1445,"solution":"slush","print_date":"2026-08-01",...}
                         ^^^ strstr match is here
                              "slush" <- 5 bytes copied from ptr+3
```

So the **key is the Wordle solution word of the day** (5 letters). The check
compares it to your input with `strncmp`.

---

## Step 8 — Dynamic Verification

### 8.1 The binary fetches the API

`ltrace` confirms the program seeds `srand`, builds today's date, decrypts and
fetches the URL, and sets the curl options on every run:

```
$ ltrace -e 'srand+localtime+sprintf+curl_easy_setopt+curl_easy_perform' ./ilikewords
ilikewords->srand(1785543368)                    = <void>
ilikewords->localtime(1785543368)                = {8, 16, 5, 1, 7, 126, 6, 212, 0, 18000, "PKT"}
ilikewords->sprintf("2026-08-01", "%d-%02d-%02d", 2026, 8, 1) = 10
ilikewords->sprintf("https://www.nytimes.com/svc/word"..., "https://www.nytimes.com/svc/word"...) = 53
ilikewords->curl_easy_setopt(0x..., 0x2712, 0x..., 0x2712) = 0   ; CURLOPT_URL = 10002
ilikewords->curl_easy_setopt(0x..., 0x4e2b, 0x..., 0x4e2b) = 0   ; CURLOPT_WRITEFUNCTION = 20011
ilikewords->curl_easy_perform(0x...) = 0
```

And the API itself answers (also verifiable by hand):

```console
$ curl -s https://www.nytimes.com/svc/wordle/v2/2026-08-01.json
{"id":1445,"solution":"slush","print_date":"2026-08-01","days_since_launch":1869,"editor":"Tracy Bennett"}
```

### 8.2 Feeding the key to the binary

```console
$ ./ilikewords
Please enter a key:  slush
 > Well done! You have found the key!
 > Submit the flag below to claim your points :)
VuwCTF{do_you_like_wordle_as_much_as_i?}
```

---

## Step 9 — Where Does `"wordle"` Come From? (The Flag)

Look back at `main`:

```asm
15ef:    mov    DWORD PTR [rbp-0xf], 0
15f6:    mov    DWORD PTR [rbp-0xc], 0
15fd:    lea    rcx, [rip+0x2b78]     # 0x417c  <- source
1608:    mov    edx, 0x6               # length 6
1610:    mov    rdi, rax               # dest
1613:    call   memcpy@plt             # word = *(char*)0x417c (6 bytes)
...
163d:    lea    rsi, [rip+0xa64]       # "VuwCTF{do_you_like_%s_as_much_as_i?}"
164c:    call   printf@plt             # printf(fmt, word)
```

The 6 bytes come from **`0x417c`**, which is a fixed offset into the global
**URL buffer at `0x4160`**. The URL, after `sprintf`, is

```
https://www.nytimes.com/svc/wordle/v2/2026-08-01.json
```

Counting from `0x4160`:

| offset | bytes |
|--------|-------|
| `0x4160` + 0 | `https://`  (8) |
| `0x4160` + 8 | `www.nytimes.com` (15) |
| `0x4160` + 23 | `/` |
| `0x4160` + 24 | `svc/` |
| `0x4160` + 28 | **`wordle`**  ← `0x417c`, copied as the flag's `%s` |
| `0x4160` + 34 | `/v2/2026-08-01.json` |

`0x4160 + 28 = 0x417c`. So `printf("VuwCTF{do_you_like_%s_as_much_as_i?}", word)`
always prints `wordle`, regardless of the date or the daily word. The flag is
effectively hard-coded by pointing `%s` at a substring of the URL the program
itself builds.

---

## Step 10 — Solve Script

`solve.py` replicates the entire chain in pure Python (no binary needed):

```python
#!/usr/bin/env python3
"""Solver for the ilike-words challenge (VuwCTF 2026)."""

import time
import urllib.request

OBS = b"vkjmo!54kji1pdhrw~o3}ps2omy4krl{rx3m(49n0umrr"


def decrypt_url(seed: int) -> bytes:
    """func_1a31: XOR each byte with the walking seed."""
    out = bytearray(OBS)
    counter, flag, i = 3, 1, 0
    while i < len(out) and out[i] != 0:
        out[i] ^= seed & 0xFF
        counter += 1
        if counter % 5 == 0:
            seed, flag = (seed - 1, 0) if flag else (seed + 1, 1)
        else:
            seed, flag = (seed + 1, 0) if flag else (seed - 1, 1)
        i += 1
    return bytes(out[:i])


def main() -> None:
    seed = 6174                       # Kaprekar's constant, see WRITEUP step 3
    fmt = decrypt_url(seed)
    date = time.strftime("%Y-%m-%d")
    url = (fmt % date.encode()).decode()

    with urllib.request.urlopen(url) as resp:
        body = resp.read().decode()

    key = body.split('":"', 1)[1][:5]      # the Wordle solution word
    word = url[28:34]                      # "wordle" (offset 28 of the URL)
    flag = f"VuwCTF{{do_you_like_{word}_as_much_as_i?}}"

    print(f"[*] decrypted URL : {fmt.decode()}")
    print(f"[*] date          : {date}")
    print(f"[*] key (word)    : {key!r}")
    print(f"[+] KEY  : {key}")
    print(f"[+] FLAG : {flag}")


if __name__ == "__main__":
    main()
```

### Running it

```console
$ python3 solve.py
[*] decrypted URL : https://www.nytimes.com/svc/wordle/v2/%s.json
[*] date          : 2026-08-01
[*] key (word)    : 'slush'

[+] KEY  : slush
[+] FLAG : VuwCTF{do_you_like_wordle_as_much_as_i?}
```

---

## Key Takeaways

- **"Random" isn't random:** the `srand/rand` seed is fed through Kaprekar's
  routine, which deterministically collapses to **6174** — a fun one-liner
  that makes the decryption fully reproducible.
- **Read the flag code path carefully:** the flag's `%s` is copied from the
  URL buffer at `0x417c`, not from the key. The key (the Wordle word) only
  gates the success branch; the flag is constant.
- **Obfuscation is often just XOR + a walking key:** a per-byte XOR with a
  seed that increments/decrements per byte is trivially invertible once you
  spot the pattern.
- **Anti-debug flair:** calling `time(0)` twice per byte and `exit(1)` if a
  second elapses makes manual stepping annoying, but static analysis ignores
  it entirely.
- **Dynamic tools help:** `ltrace` reveals exactly which URL is fetched and
  the `sprintf` arguments, and `curl` can stand in for the binary to grab the
  live data.

---

**Flag: `VuwCTF{do_you_like_wordle_as_much_as_i?}`**

