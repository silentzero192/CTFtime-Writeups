# Cascading the Seven Seas - Writeup

## Challenge Info

- **Name**: `cascading seven seas`
- **Category**: `Web`
- **Description**: `don't worry i consulted a marine biologist on this one...`
- **Challenge URL**: <https://css.ctf.ritsec.club/>
- **Flag format**: `RS{...}`

## Overview

This challenge is a browser-side virtual machine implemented almost entirely in CSS.

The page exposes a fake keyboard, a screen, and a giant stylesheet full of custom properties like:

```css
@property --m0 { initial-value: 204; }
@property --m1 { initial-value: 144; }
...
@property --m8448 { initial-value: 0; }
```

Those `--mN` variables are the VM memory image. A small bit of JavaScript advances a CSS clock, and the CSS rules update registers and memory between frames. In other words, the browser is being abused as an emulator.

Rather than trying to solve it interactively by clicking buttons, the clean path is:

1. Download the HTML.
2. Extract the embedded memory image from the `@property --mN` declarations.
3. Reconstruct the program bytes.
4. Reverse the checker logic.
5. Solve the resulting constraints with Z3.

## Initial Recon

Fetching the page source immediately shows the important components:

- A fake keyboard where each button maps to an ASCII code through CSS selectors.
- A huge block of `@property --mN` definitions that store memory bytes.
- Initial register values such as `--IP: 769`, meaning execution starts at `0x301`.
- A tiny JavaScript loop that repeatedly advances the CSS VM clock.

The keyboard mapping is visible directly in the page:

```css
&:has(key-board button:nth-child(11):hover:active) { --keyboard: 81; }
...
&:has(key-board button:nth-child(30):hover:active) { --keyboard: 123; }
```

That tells us the program only accepts characters from:

```text
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ{}_
```

## Extracting The Memory Image

The memory bytes are stored as CSS custom properties:

```css
@property --m0 {
  syntax: "<integer>";
  initial-value: 204;
}
```

I extracted them with a simple regex:

```python
matches = re.findall(
    r'@property --m(\d+) \{\s*syntax: "<integer>";\s*initial-value: (\d+);',
    html,
)
memory = {int(index): int(value) for index, value in matches}
```

After rebuilding the byte array, printable strings already reveal the program theme:

```text
You win!!! Press any key to exit
Incorrect. Press any key to exit
3. What's the flag?:
2. Name an aquatic mammal:
1. Which ocean is the largest?:
Welcome to:
...PIRATE TRIVIA!
Let's get started...
```

That also explains the challenge description joke: one of the “marine biology” answers is not even a marine animal.

## Disassembly

The initial instruction pointer is `0x301`, so the extracted memory can be treated like a tiny 16-bit binary and disassembled around that entry point.

Important functions:

### `0x100` - print string

This routine walks a null-terminated string and prints it one character at a time.

### `0x11e` - read input

This reads characters from the CSS keyboard into a buffer until `RETURN` (`0x0a`) or the input limit is reached.

### `0x1a6` - constraint checker

This is the most important routine. It does **not** compare against a plaintext answer. Instead, it reads 8-byte records from a table and checks a small arithmetic/XOR relation over the input bytes.

Each record is:

```text
u16 index_a
u16 index_b
u16 index_c
u16 target
```

The check performed for each row is:

```python
input[index_a] ^ (input[index_b] + input[index_c]) == target
```

So the answers are stored as systems of equations, not hardcoded strings.

### `0x248` - main challenge flow

The main routine asks three questions:

1. Largest ocean
2. An aquatic mammal
3. The flag

It validates them against three tables:

- `0x470` for question 1
- `0x420` for question 2
- `0x320` for the flag

## Solving The Equations

Because the keyboard alphabet is small and the equations are simple, Z3 solves them immediately.

I modeled each input byte as a 16-bit symbolic value constrained to the on-screen keyboard alphabet:

```python
for a, b, c, target in table:
    solver.add((chars[a] ^ (chars[b] + chars[c])) == target)
```

Solutions:

- Question 1: `PACIFIC`
- Question 2: `HORSE`
- Flag: `RS{CR3D1T_T0_LYR4_R3B4N3_F1BDF5}`

`HORSE` is the payoff to the description joke. The prompt says “aquatic mammal,” but the actual accepted answer is just `HORSE`.

## Solver Script

I added [solution.py](/home/jilani/Desktop/ritsecCTF-2026/web/cascading-seven-seas/solution.py), which:

- fetches the challenge HTML or reads a saved local copy
- extracts the CSS VM memory
- parses the three constraint tables
- solves them with Z3
- prints the two trivia answers and the final flag

Run it against a saved page:

```bash
curl -sS https://css.ctf.ritsec.club/ -o challenge.html
python3 solution.py challenge.html
```

Or let it fetch the site directly:

```bash
python3 solution.py
```

Expected output:

```text
Question 1 answer: PACIFIC
Question 2 answer: HORSE
Flag: RS{CR3D1T_T0_LYR4_R3B4N3_F1BDF5}
```

## Why This Works

The challenge looks like a web exploit puzzle, but the real task is reversing a bizarre CSS-based emulator.

Once the HTML is treated as a packed binary:

1. The strings reveal the quiz flow.
2. The entry point reveals a small 16-bit program.
3. The checker reduces to straightforward symbolic constraints.
4. The flag falls out directly.
