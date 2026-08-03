# cc — VuwCTF 2026 (Reversing)

| | |
|---|---|
| **Category** | Reversing |
| **File** | `cc.cpython-314.pyc` (29,801 bytes) |
| **Difficulty** | Medium–Hard |
| **Flag** | `VuwCTF{_call_Crypt0C0ntinuati0n}` |

> An obfuscated Python bytecode challenge that hides a hand-rolled AES-256
> implementation behind church-encoded combinators, `functools.partial`, and
> Python 3.14's brand-new bytecode. The "hash" it computes on your input is
> nothing but **AES-256-CBC with a fixed key and a zero IV** — recover the key
> and decrypt the target.

---

## TL;DR

1. The `.pyc` is a Python 3.14 module (`source name: coro_anom.py`) that reads
   a 32-char flag, encrypts it with a fixed AES-256 key using CBC with a zero
   IV, and compares the ciphertext to a hard-coded 32-byte constant.
2. After un-flattening the combinator soup, every component of AES is there:
   `gc()` builds the standard AES S-box, `gg()` is the AES-256 key schedule,
   `gd`/`ge`/`gf` are SubBytes/ShiftRows/MixColumns and `gh` is AddRoundKey.
3. The key and S-box are **constants** (computed deterministically at import),
   so we extract them from a single instrumented run and decrypt the target
   with textbook AES-256-CBC.

```
$ python3.14 solve.py
[*] loaded cc.cpython-314.pyc (29801 bytes, magic 2b0e0d0a)
[*] target ciphertext : f6504e32e2e56c9c8474fc923d3fce8a383a9c2fe90cbf6b01f410bb27f4165d
[*] recovered AES-256 key : 0683c1e070b85cae57ab55aad5eaf5fa7d3e9f4fa75329140a85422190c8e4f2
[+] flag               : VuwCTF{_call_Crypt0C0ntinuati0n}
[*] challenge output   : Correct
```

---

## 0. Environment notes (important!)

* The tag says `cpython-314`, so the file **must** be executed/disassembled
  with a real **Python 3.14** interpreter. On this box `/usr/bin/python3.14`
  is `3.14.4`; the `~pwnEnv/bin/python3.14` shim is a symlink to Python 3.12
  and will fail to load the bytecode (marshal version mismatch).
* Everything after the 16-byte pyc header is one `marshal` blob, so we can
  load it without ever running it:

```python
import marshal
code = marshal.loads(open("cc.cpython-314.pyc","rb").read()[16:])
```

---

## 1. Recon

```console
$ file cc.cpython-314.pyc
cc.cpython-314.pyc: Byte-compiled Python module for CPython 3.14, timestamp-based, size 29801

$ python3.14 -c "import struct; d=open('cc.cpython-314.pyc','rb').read(16); print(d[:4].hex())"
2b0e0d0a        # magic 0x0a0d0e2b = CPython 3.14, marshal v5
```

Dumping the code-object tree with `marshal` gives us the layout. The top-level
module defines a single class `cls` and a zoo of functions:

```text
co_names of <module>: functools partial sys setrecursionlimit cls ga gb gc gd ge gf
                      gg gh gi gj gk gl gm gn go gp f z print
co_consts:            <code cls @8> <code ga @52> <code gb @64> <code gc @68>
                      <code gd @120> <code ge @124> <code gf @151> <code gg @201>
                      <code gh @245> <code gi @249> <code gj @253> <code gk @256>
                      <code gl @274> <code gm @301> <code gn @305> <code go @314>
                      <code gp @318> <code <lambda> @333> <code <lambda> @335>
```

We immediately notice new Python 3.14 opcodes everywhere
(`LOAD_FAST_BORROW`, `LOAD_FAST_BORROW_LOAD_FAST_BORROW`,
`STORE_FAST_STORE_FAST`, `LOAD_SMALL_INT`, `LOAD_COMMON_CONSTANT`,
`COPY_FREE_VARS`, `CALL_INTRINSIC_1`, `RETURN_GENERATOR`, ...), so `dis` from
any older Python won't do — use the 3.14 disassembler.

---

## 2. The program's real behaviour

Executing the module with `input` replaced by `print` shows it just prints
`Incorrect` (or `Correct`). Looking at the tail of the module disassembly the
whole program is:

```text
gc().f(λ333).f(λ335).z
```

with the final comparison:

```text
def <λ335 / check>(v):
    target = 111410848224773142892496866455170858706213881814095825670355898978049688082013
    return "Correct" if all(w == x for (w, x) in zip(v, target.to_bytes(32))) else "Incorrect"
```

> Note: `int.to_bytes(32)` with **one** argument is a new Python 3.14 feature
> (byteorder defaults to `big`). Older Python would raise `TypeError` here.
> So the target is:

```python
target = 111410848224773142892496866455170858706213881814095825670355898978049688082013
target.to_bytes(32).hex()
# f6504e32e2e56c9c8474fc923d3fce8a383a9c2fe90cbf6b01f410bb27f4165d
```

`gn()` (line 305) is the input handler:

```text
def gn():
    return cls.a(input("Flag: ")).b(lambda p: p.encode()) \
             .g(lambda q: gm(len(q) == 32)) \
             .b(lambda r: (r[:16], r[16:]))
```

So: read a flag → UTF-8 encode → **assert length == 32** (`gm` is `assert`) →
split into two 16-byte halves.

Everything else is a big obfuscated "black box" that maps the 32 flag bytes to
the 32 bytes compared against `target`. The question is: what is that box?

---

## 3. Black-box analysis of the transform

Before reading any more bytecode, treat the module as an oracle: run it with a
known flag and intercept the value fed into the final `zip` (wrap the builtin
`zip` and log its first argument). Varying a single input byte shows:

| changed input byte | changed output bytes |
|---|---|
| `flag[0..15]` | **all 32** |
| `flag[16..31]` | only **bytes 16..31** |

This is exactly the dependency structure of **CBC mode with a zero IV**:

* `out[0:16] = E(s0)` depends only on `s0 = flag[0:16]`
* `out[16:32] = E(s1 ⊕ ct0)` depends on `s1 = flag[16:32]` **and** `ct0`

So the transform is a block cipher over 16-byte blocks, chained in CBC. We
need to find out which block cipher.

---

## 4. De-obfuscating: the code is AES-256

The whole program is written in a "point-free" style using the class `cls`,
whose methods return little combinator objects (`.f()`, `.b()`, `.g()`,
`.h()` are all "apply some function to the stored value" / "build a pair"
helpers), plus `functools.partial`. Un-flattening the 3.14 disassembly of each
top-level function reveals extremely recognizable primitives.

### 4.1 `gb(a, b)` — rotate left

```text
def gb(a, b):
    return ((a << b) | (a >> (8 - b))) % 256
```

`rotl8`. Used everywhere GF(2^8) arithmetic appears.

### 4.2 `gc()` — the AES S-box

`gc()` starts with `buff = [99] * 256` and iteratively fills it using the
classic multiplicative-inverse + affine-transform construction. The inner
lambdas are:

```text
line 81: q = q ^ (q << 1)      # multiply by x
line 82: q = q % 256
line 83: q = q ^ (q << 2)
line 84: q = q % 256
line 85: q = q ^ (q << 4)
line 86: q = q % 256
line 87: q = q ^ (q & 0x80 ? 9 : 0)     # reduce mod 0x11b
line 88: q = q % 256
...
line 92..94:  p = p ^ (p << 1); p = p ^ (p & 0x80 ? 27 : 0)   # xtime
line 98..102: x = w ^ gb(q,1) ^ gb(q,2) ^ gb(q,3) ^ gb(q,4); q0 = (p, q ^ x ^ 99)
```

This is the textbook AES S-box generation loop. Indeed, at runtime the buffer
equals the standard AES S-box:

```text
buff[0:16]  = 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
```

`gc()` returns an object whose value is this 256-entry S-box.

### 4.3 `gg(c, b)` — the AES-256 key schedule

`gg` first asserts `len(b) == 8` and that every word fits in 32 bits, then
runs the well-known AES-256 key-expansion recurrence:

```text
z = [ b[s] for s in < 8 ]
for s in 8..:
    if s % 8 == 0:  z.append(z[-8] ^ SubWord(RotWord(z[-1])) ^ Rcon(s//8))
    elif s % 8 == 4: z.append(z[-8] ^ SubWord(z[-1]))
    else:           z.append(z[-8] ^ z[-1])
```

* `SubWord` = `int.from_bytes([c[b] for b in word.to_bytes(4)])` — i.e. apply
  the S-box `c` to the 4 bytes.
* `RotWord` = `((w & 0xFFFFFF) << 8) | (w >> 24)`.
* `Rcon` = `2**(s//8) << 23` (the round constant in the top byte).

That is exactly AES-256 key expansion with `b` = the 8×32-bit key words.

### 4.4 `gd`, `ge`, `gf`, `gh` — the AES round

* `gd(a, b)` = `[b[x] for x in a]` → **SubBytes** (lookup through table `b`).
* `ge` works on a 16-byte state with a `4×4` layout (`out[i*4 + (i+r)%4]` …)
  → **ShiftRows**.
* `gf` implements the MixColumns arithmetic, including the GF(2^8) `xtime`
  pattern `(p << 1) % 256 ^ 27 * (p >> 7)` → **MixColumns**.
* `gh(a, b)` = `[x ^ y for x, y in zip(a, b)]` → **AddRoundKey** (XOR).

### 4.5 `gl(a, b, c)` — one AES block encryption

```text
def gl(key, block, sbox):
    rounds = gk(gg(sbox, key))          # expanded round keys
    state  = AddRoundKey(block, roundkey[0])
    for r in 1..13:
        state = AddRoundKey(MixColumns(ShiftRows(SubBytes(state))), roundkey[r])
    state = AddRoundKey(ShiftRows(SubBytes(state)), roundkey[14])
    return state
```

The recursion counter in `gk` is seeded with `13`; combined with the initial
and final `AddRoundKey` this is the standard **14-round AES-256**.

### 4.6 Putting it together — the CBC chain

The module tail unwraps to:

```python
f  = lambda p: gp().b(lambda q: (q, p))        # p = S-box, q = derived key words
z  = lambda r: gn().f(lambda s:
              gl(r[0], s[0], r[1]).f(lambda t:
              gl(r[0], go(t, s[1]), r[1]).b(lambda u: t + u)))
print(z.z)
```

with `go(a, b) = bytes(x ^ y for x, y in zip(a, b))`. So:

```python
s0, s1   = flag[:16], flag[16:]
ct0      = AES256(s0)                 # IV = 0
ct1      = AES256(s1 XOR ct0)
v        = ct0 + ct1
assert v == target                     # the final zip/all check
```

**It is stock AES-256-CBC with a zero IV.**

---

## 5. Extracting the parameters

The key (from `gp()`) and the S-box (from `gc()`) are computed once,
deterministically, at import time — they don't depend on the flag. So we
observe a single run and tap the block-cipher entry point `gl` with
`sys.settrace`:

```python
import sys, marshal
code = marshal.loads(open("cc.cpython-314.pyc","rb").read()[16:])

captured = {}
def trace(frame, event, arg):
    if event == "call" and frame.f_code.co_name == "gl" and "key" not in captured:
        captured["key"]  = list(frame.f_locals["a"])   # 8 x 32-bit words
        captured["sbox"] = list(frame.f_locals["c"])   # 256 bytes
        captured["blk"]  = list(frame.f_locals["b"])   # first CBC plaintext
    return None

sys.settrace(trace)
exec(code, {"__name__":"__main__", "__builtins__":__import__("builtins"),
            "input": lambda p="": "A"*32, "print": lambda *a,**k: None})
sys.settrace(None)
```

Result (the S-box head confirms stock AES):

```text
key words = [109298144, 1891130542, 1470846378, 3588945402,
             2101256015, 2807245076,  176505377, 2429084914]
key       = 0683c1e070b85cae57ab55aad5eaf5fa7d3e9f4fa75329140a85422190c8e4f2
sbox      = 637c777bf26b6fc53001672bfed7ab76 ...   (standard AES S-box)
first blk = [65]*16                                 (input "A"*32, IV = 0)
```

**Sanity check.** Encrypt `"A"*16` with stock AES-256-CBC (key above, IV=0)
and compare with the oracle output for `"A"*32`:

```text
AES-256-CBC(0, "A"*16) -> 333d4756a811d00745a1133af6b6ae45
oracle v[0:16]         -> 333d4756a811d00745a1133af6b6ae45     ✓ identical
```

The challenge literally implements standard AES-256.

---

## 6. Solving

`v == target` means the flag is the plaintext:

```python
flag = AES256_CBC_decrypt(key, iv=0, ct=target)
```

The final check compares against a constant the author produced by running the
program on the real flag, so decryption is trivial:

```text
VuwCTF{_call_Crypt0C0ntinuati0n}
```

---

## 7. Script

`./solve.py` (no third-party dependencies — a from-scratch AES-256 is
embedded, verified against the oracle):

1. loads the pyc with `marshal`,
2. extracts `target` from the bytecode constants (the only 256-bit literal,
   serialized with 3.14's one-arg `int.to_bytes`),
3. recovers the key words + S-box by tapping `gl` in one instrumented run,
4. decrypts `target` with pure-Python AES-256-CBC (IV = 0),
5. verifies by re-encrypting and by running the real module (prints `Correct`).

```console
$ python3.14 solve.py
[*] loaded cc.cpython-314.pyc (29801 bytes, magic 2b0e0d0a)
[*] target ciphertext : f6504e32e2e56c9c8474fc923d3fce8a383a9c2fe90cbf6b01f410bb27f4165d
[*] recovered AES-256 key : 0683c1e070b85cae57ab55aad5eaf5fa7d3e9f4fa75329140a85422190c8e4f2
[*] S-box is the standard AES S-box
[*] key words            : [109298144, 1891130542, 1470846378, 3588945402, 2101256015, 2807245076, 176505377, 2429084914]
[+] flag               : VuwCTF{_call_Crypt0C0ntinuati0n}
[*] re-encryption matches TARGET
[*] challenge output   : Correct
```

---

## 8. Key takeaways

* **Obfuscation does not change the algorithm.** The combinator/closures
  wrapper is exactly as strong as the crypto it wraps — and here the crypto is
  vanilla, off-the-shelf AES-256 with a hard-coded key.
* **`zip`/`all`/`input` monkey-patching + `sys.settrace`** are a fast way to
  turn an opaque pyc into an oracle, and to dump parameters of "keyed"
  computations without full static reversal.
* **Watch for interpreter-specific features.** The one-argument
  `int.to_bytes(32)` in the comparison is a Python 3.14-only API and also a
  nice fingerprint that the challenge really was compiled for 3.14.
* The S-box construction, key schedule and round functions are unambiguous
  AES signatures — learning to recognize these patterns in disassembly is the
  fastest path to solving.

*Flag: `VuwCTF{_call_Crypt0C0ntinuati0n}`*
