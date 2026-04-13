# Mark Compass

## Challenge Info

- **Name:** `mark compass`
- **Category:** `Crypto`
- **Description:** `Old Captain Mark was the most erratic pirate on the seven seas. They say his compass was cursed! It didn't point North, but spun wildly, giving coordinates based on the Captain's shifting mood (though he generally preferred to stay his course).`
- **Flag format:** `RS{...}`

## Files Provided

```text
logbook.txt
navigate.py
```

`navigate.py` is the important file. It describes the generator used to produce the 850 logged values and then encrypt the flag.

## Source Review

The challenge code is:

```python
import random

from Crypto.Util.number import getPrime

matrix = [line.strip() for line in open("tmatrix.txt") if line.strip()]

N = len(matrix)
PROBS = [[float(x) for x in line.split()] for line in matrix]


def gen_params():
    P = getPrime(random.randint(256, 1024))
    heads = []
    for _ in range(N):
        a = random.randint(2, P - 1)
        b = random.randint(2, P - 1)
        heads.append((a, b))
    return P, heads


class StateMachine:
    def __init__(self, P, heads, trans):
        self.P = P
        self.heads = heads
        self.trans = trans
        self.curr = random.randint(0, len(heads) - 1)
        self.sval = random.randint(0, P - 1)

    def next(self):
        a, b = self.heads[self.curr]
        self.sval = (a * self.sval + b) % self.P

        val = random.random()
        total = 0.0
        row = self.trans[self.curr]
        nxt = self.curr

        for i, prob in enumerate(row):
            total += prob
            if val < total:
                nxt = i
                break

        self.curr = nxt
        return self.sval


def enc(flag, lcg):
    fbytes = flag.encode()
    strm = [lcg.next() & 0xFF for _ in range(len(fbytes))]

    return bytes([k ^ f for k, f in zip(strm, fbytes)])
```

So the output is **not** a single LCG. It is a **hidden Markov model** where each state has its own affine recurrence:

```text
x_{t+1} = a_s * x_t + b_s mod P
```

After each step, the machine probabilistically transitions to another state according to the missing `tmatrix.txt`.

The challenge gives us:

- 850 raw outputs
- the final ciphertext
- no modulus `P`
- no head parameters `(a, b)`
- no transition matrix

That sounds nasty, but there is a very nice weakness:

- the chain often stays in the same state
- every state uses the same modulus `P`
- the flag format gives a strong plaintext anchor

## Data Triage

First inspect `logbook.txt`.

```bash
python3 - <<'PY'
import ast
from pathlib import Path

text = Path("logbook.txt").read_text()
log = ast.literal_eval(text.split("Log: ", 1)[1].split("\nCiphertext:", 1)[0])
ct = bytes.fromhex(text.split("Ciphertext: ", 1)[1].strip())

print("log length:", len(log))
print("ciphertext bytes:", len(ct))
print("min bit length:", min(x.bit_length() for x in log))
print("max bit length:", max(x.bit_length() for x in log))
PY
```

Output:

```text
log length: 850
ciphertext bytes: 34
min bit length: 821
max bit length: 835
```

That already tells us the prime modulus is probably around 835 bits.

## Step 1: Recover The Modulus

For a normal affine generator

```text
y = a*x + b mod P
z = a*y + b mod P
w = a*z + b mod P
```

the standard LCG determinant relation holds:

```text
(w - z)(y - x) - (z - y)^2 ≡ 0 mod P
```

If the generator stayed in one state forever, taking a GCD across many such values would reveal `P`.

Here the state changes, so most windows are "dirty" and the relation does not always hold. But because the chain often remains in the same state, a lot of short windows still contribute multiples of `P`.

The trick is to compute local GCDs and look for a repeated large factor:

```bash
python3 - <<'PY'
import ast
import math
from pathlib import Path
from collections import Counter

text = Path("logbook.txt").read_text()
log = ast.literal_eval(text.split("Log: ", 1)[1].split("\nCiphertext:", 1)[0])

mods = []
for i in range(len(log) - 5):
    x0, x1, x2, x3, x4, x5 = log[i:i+6]
    a = (x2 - x1) * (x4 - x3) - (x3 - x2) * (x3 - x2)
    b = (x3 - x2) * (x5 - x4) - (x4 - x3) * (x4 - x3)
    g = math.gcd(abs(a), abs(b))
    if g > 1000:
        mods.append(g)

from functools import reduce
P = reduce(math.gcd, mods)
print(P)
PY
```

Recovered modulus:

```text
114998001088122878165469494209865851580646945385760011250661037287215114047884823814201471683151719773292295650809857617855325511069020132311210674811529707856845753203740687736866355160800098819362158152761107736460621045328980768188047601931528470157
```

Check that it is actually prime:

```bash
python3 - <<'PY'
from Crypto.Util.number import isPrime

P = 114998001088122878165469494209865851580646945385760011250661037287215114047884823814201471683151719773292295650809857617855325511069020132311210674811529707856845753203740687736866355160800098819362158152761107736460621045328980768188047601931528470157
print(isPrime(P))
PY
```

Output:

```text
True
```

So we have the correct modulus.

## Step 2: Recover The Hidden Heads

Let a triple of consecutive outputs be:

```text
x, y, z
```

If the **same head** was used for both transitions, then:

```text
y = a*x + b mod P
z = a*y + b mod P
```

which gives:

```text
a = (z - y) * (y - x)^(-1) mod P
b = y - a*x mod P
```

Now compute `(a, b)` for every triple and count how often each pair appears.

Important detail:

- a repeated `(a, b)` only appears when the same head was used twice in a row
- so the most common recovered pairs are the real heads

```bash
python3 - <<'PY'
import ast
from pathlib import Path
from collections import Counter

P = 114998001088122878165469494209865851580646945385760011250661037287215114047884823814201471683151719773292295650809857617855325511069020132311210674811529707856845753203740687736866355160800098819362158152761107736460621045328980768188047601931528470157

text = Path("logbook.txt").read_text()
log = ast.literal_eval(text.split("Log: ", 1)[1].split("\nCiphertext:", 1)[0])

params = []
for i in range(len(log) - 2):
    x, y, z = log[i:i+3]
    den = (y - x) % P
    if den == 0:
        continue
    a = ((z - y) % P) * pow(den, -1, P) % P
    b = (y - a * x) % P
    params.append((a, b))

for idx, (pair, count) in enumerate(Counter(params).most_common(5), 1):
    print(idx, count, pair)
PY
```

The top 5 pairs are the 5 real heads:

```text
1 140 (5979614717508458085708465813571678544325762321058302037763644471654634168297938035875326849893345873864148531569186363250375421883072518267425329061945646231477022769073763738064349989536570722079552632589628201196413993423475498345946353384713035586, 114910064404367269078145582556764821009386979808309011456017431136057066292802459142293882930149865756442645119159245594545508125545443622705312185035542484383581680609119988326779933810319836014222300724723195321672341400719191660836496681577936525188)
2 118 (91621451643556352541726259759842187154005806485753405994985795824337757018651101518826334112512501579708171329276478101950199195117232991978440358410981615814686867892088693247086104231332560720431665843488414418050064458319094648762113159298295745040, 90982482191425544587392382740589333347846604619831437807558507671993880148610435561170047146645910843040020828459646800431402458236291016123456097653549397003074538598984320183285869933863540293356702451506617924494130205023574813500619543558240946431)
3 114 (11372551066942027930913354393528527346918684173382956965332180121955807681021602938929687077967421550031342140405735960033141667886485192550322948616930869487576434836257053519344257725800816871985337366815629498270789484588550218502855338972914425134, 29841215611803029620019326380500258266092991528620544751420273056050056386443904499372529966707788961186280831284339801582122577977739774237065904545597081466218507420931889595082788013970491091765139132190957474974424526621727794251045710889466281911)
4 112 (69644897663408960589455998158726336247680978358920878663727503365080685045074798334296390026502317774278026827574740757607129048738737007430154926524283230170656782384351647405119506124438126277465718431837358449181363535273331712088784481021784708634, 57156060515645524518187939095406211023328595382138090572026093833377945674140192031465160951727775741560696489685561303955902461559715391340555049708610638743459624909975780918652696576211705742664397525483828705196142121551936077515648445423202073631)
5 88 (71673535623239156631331324707429057744809326213728843357749019266449740600916745020504438447827986508770245110024470805103494091520079456935756256948263978546933293850783990955796448963157859221022323105862081932294609374225899418818562870211651771489, 79988630305543601669690342477361425569759932153829508596009554825701573512304384252768711076428027188201457636719549940864905668880242558337692839868910813620857367563737649714023589868605908436077660288136019769574429626049099280629583176879884856166)
```

So `N = 5`, even though `tmatrix.txt` was not provided.

## Step 3: Recover The Hidden State Sequence

Now that we know `P` and the 5 heads, every adjacent pair in the log can be labeled uniquely:

```text
x_{i+1} = a_j * x_i + b_j mod P
```

for exactly one head `j`.

That reconstructs the hidden state path for all 849 transitions in the 850-value log.

Running that gives:

```text
Head usage:
state 0: 199
state 1: 164
state 2: 165
state 3: 173
state 4: 148
```

Transition counts:

```text
state 0 -> {0: 140, 1: 13, 2: 18, 3: 12, 4: 16}
state 1 -> {0: 8, 1: 118, 2: 13, 3: 12, 4: 13}
state 2 -> {0: 21, 1: 6, 2: 114, 3: 12, 4: 12}
state 3 -> {0: 10, 1: 20, 2: 12, 3: 112, 4: 19}
state 4 -> {0: 20, 1: 6, 2: 8, 3: 25, 4: 88}
```

This matches the challenge flavor perfectly:

- the compass is erratic
- but it still has a strong preference to keep its course
- each state has a large self-transition count

## Step 4: Decrypt The Ciphertext

At the end of the 850 logged outputs, the machine state is not fully known:

- we know the current internal numeric value is the last logged output
- we know the last head used in the log
- but the next head is chosen probabilistically by the hidden transition matrix

The ciphertext is only 34 bytes long, and the flag must start with `RS{` and end with `}`.

That makes the final step tractable:

1. Start from the last logged value.
2. Try all 5 possible next heads.
3. Keep only branches that decrypt to a valid flag prefix.
4. Score branches using the recovered transition counts.
5. Use a beam search to keep only the most plausible candidates.

### Why the prefix is enough

The first few bytes are extremely constraining.

For the first ciphertext byte, only one next state decrypts to `R`.

For the second ciphertext byte, only one continuation decrypts to `S`.

For the third ciphertext byte, only one continuation decrypts to `{`.

After that, restricting the interior to:

```text
[A-Za-z0-9_]
```

is enough for the beam search to lock onto one dominant candidate.

## Solver Sketch

This is the core structure of the solve:

```python
import ast
import math
import string
from pathlib import Path
from collections import Counter, defaultdict
from Crypto.Util.number import isPrime

text = Path("logbook.txt").read_text()
log = ast.literal_eval(text.split("Log: ", 1)[1].split("\nCiphertext:", 1)[0])
ct = bytes.fromhex(text.split("Ciphertext: ", 1)[1].strip())

# Recover P
mods = []
for i in range(len(log) - 5):
    x0, x1, x2, x3, x4, x5 = log[i:i+6]
    a = (x2 - x1) * (x4 - x3) - (x3 - x2) * (x3 - x2)
    b = (x3 - x2) * (x5 - x4) - (x4 - x3) * (x4 - x3)
    g = math.gcd(abs(a), abs(b))
    if g > 1000:
        mods.append(g)

from functools import reduce
P = reduce(math.gcd, mods)
assert isPrime(P)

# Recover heads from repeated same-state triples
params = []
for i in range(len(log) - 2):
    x, y, z = log[i:i+3]
    den = (y - x) % P
    if den == 0:
        continue
    a = ((z - y) % P) * pow(den, -1, P) % P
    b = (y - a * x) % P
    params.append((a, b))

heads = [pair for pair, _ in Counter(params).most_common(5)]

# Label each adjacent pair with its unique head
states = []
for i in range(len(log) - 1):
    x, y = log[i], log[i + 1]
    for j, (a, b) in enumerate(heads):
        if (a * x + b) % P == y:
            states.append(j)
            break

# Estimate transition probabilities from counts
trans = defaultdict(Counter)
for a, b in zip(states, states[1:]):
    trans[a][b] += 1

logp = [[0.0] * 5 for _ in range(5)]
for s in range(5):
    total = sum(trans[s].values()) + 5
    for t in range(5):
        logp[s][t] = math.log((trans[s][t] + 1) / total)

# Beam search the ciphertext
allowed_inner = set((string.ascii_letters + string.digits + "_").encode())
beam = [(0.0, log[-1], states[-1], "")]

for i, c in enumerate(ct):
    new = []
    for score, val, prev_state, pt in beam:
        for nxt_state, (a, b) in enumerate(heads):
            nv = (a * val + b) % P
            ch = (nv & 0xff) ^ c

            if i == 0 and ch != ord("R"):
                continue
            if i == 1 and ch != ord("S"):
                continue
            if i == 2 and ch != ord("{"):
                continue
            if i == len(ct) - 1 and ch != ord("}"):
                continue
            if 2 < i < len(ct) - 1 and ch not in allowed_inner:
                continue

            new.append((score + logp[prev_state][nxt_state], nv, nxt_state, pt + chr(ch)))

    new.sort(key=lambda x: x[0], reverse=True)
    beam = new[:200000]

print(beam[0][3])
```

## Deterministic Verification

Once the plaintext is guessed, it can be checked byte-by-byte.

For each ciphertext byte:

```text
target_keystream_byte = ciphertext_byte XOR plaintext_byte
```

Then test which head produces a next output whose low byte matches that target.

For the final recovered flag, every step matches **exactly one** head, yielding a unique path:

```text
[3, 3, 3, 2, 2, 2, 2, 4, 4, 2, 0, 1, 1, 1, 1, 3, 4, 3, 3, 0, 2, 2, 2, 2, 2, 0, 0, 0, 0, 2, 0, 4, 4, 4]
```

That reproduces the flag exactly, so the solve is not just heuristic at the end.

## Why The Challenge Breaks

The intended weakness is the combination of:

- one shared modulus across all heads
- high self-transition probability
- many raw outputs before encryption
- a short flag with a known prefix

Even though the transition matrix and parameters are missing, the long output log leaks:

1. the modulus
2. the individual affine heads
3. the hidden-state trace for the observed log
4. enough transition information to rank future state paths

So the "cursed compass" is really a leaky hidden-state LCG system.

## Final Flag

```text
RS{w04h_h1dd3n_M4rk0v_br34k5_LCGs}
```
