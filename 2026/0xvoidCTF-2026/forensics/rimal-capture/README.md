# Rimal Capture - Forensics Writeup

## Challenge Information

- **Name:** `Rimal Capture`  
- **Category:** `Forensics`  
- **Description:** `An incident capture mixes routine traffic with one operator session. The final text was not entered as cleanly as the first pass suggests.`

---

## Initial Analysis

The challenge provides a single `.pcapng` packet capture file. The description hints at two key observations:
1. Traffic is a mix of "routine" and "operator session" activity
2. Text was "not entered as cleanly" — suggesting corrections, typos, or backspaces

Let's start by examining the capture file.

```bash
$ tshark -r 39pa2x.pcapng 2>&1 | head -5
   1   0.000000     10.9.0.5 → 10.9.0.9     UDP 105 5555 → 80 Len=63
   2 -78960858.732975     10.9.0.8 → 10.9.0.9     UDP 53 41000 → 31337 Len=11
   3 -78960858.730975     10.9.0.8 → 10.9.0.9     UDP 53 41000 → 31337 Len=11
   4 -78960858.714975     10.9.0.8 → 10.9.0.9     UDP 53 41000 → 31337 Len=11
```

The capture contains **173 packets** across two distinct communication streams:

| Stream | Source | Destination | Protocol | Port |
|--------|--------|-------------|----------|------|
| HTTP-like | `10.9.0.5` | `10.9.0.9` | UDP | `5555 → 80` |
| HID Keyboard | `10.9.0.8` | `10.9.0.9` | UDP | `41000 → 31337` |

---

## Stream 1: The HTTP Decoy (Port 80)

A single UDP packet is sent to port 80. Let's extract and decode its payload:

```bash
$ tshark -r 39pa2x.pcapng -Y "udp.dstport == 80" -T fields -e data
474554202f20485454502f312e310d0a557365722d4167656e743a203078563031447b687474705f757365725f6167656e745f69735f626169747d0d0a0d0a
```

Decoding the hex:

```bash
$ python3 -c "print(bytes.fromhex('474554...').decode())"
```

```http
GET / HTTP/1.1
User-Agent: 0xV01D{http_user_agent_is_bait}
```

The User-Agent field contains a value that looks like a flag — `0xV01D{http_user_agent_is_bait}`. However, the value itself literally says **"bait"**. This is a deliberate decoy placed to catch solvers who stop at the first flag-looking string they find.

---

## Stream 2: HID Keyboard Capture (Port 31337)

The remaining **172 packets** are sent to port `31337` (a common CTF/hacker port). Each packet is 53 bytes and contains a payload prefixed with the ASCII string `HID`. These are USB HID keyboard scan codes.

### USB HID Report Structure

A standard USB keyboard HID report is 8 bytes:

| Byte | Field | Description |
|------|-------|-------------|
| 0 | Modifier | Bitmask for modifier keys (Ctrl, Shift, Alt, GUI) |
| 1 | Reserved | Reserved/OEM |
| 2-7 | Keycodes | Up to 6 simultaneous key press codes (HID Usage IDs) |

In this capture, the payload after the `HID` prefix is 9 bytes, but only the first 3 are meaningful:
- **Byte 0:** Modifier byte
- **Byte 1:** Always `0x00` (reserved)
- **Byte 2:** Single keycode (the key being pressed)
- **Bytes 3-8:** All zeros (padding)

The packets alternate between key-press events (non-zero keycode) and key-release events (all zeros). We only need to process the non-zero packets.

### Modifier Byte Breakdown

| Bit | Modifier |
|-----|----------|
| 0 | Left Ctrl |
| 1 | **Left Shift** |
| 2 | Left Alt |
| 3 | Left GUI |
| 4 | Right Ctrl |
| 5 | **Right Shift** |
| 6 | Right Alt |
| 7 | Right GUI |

Packets with modifier `0x02` have **Left Shift** held down.

### HID Usage ID → Character Mapping

The keycodes (byte 2) map to characters using the USB HID Usage Table for Keyboard/Keypad:

| Usage ID | Key | Usage ID | Key |
|----------|-----|----------|-----|
| 0x04-0x1d | a-z | 0x1e-0x27 | 1-0 |
| 0x28 | Return/Enter | 0x2a | Backspace |
| 0x2b | Tab | 0x2c | Space |
| 0x2d | - | 0x2e | = |
| 0x2f | [ | 0x30 | ] |
| 0x33 | ; | 0x34 | ' |
| 0x35 | ` | 0x36 | , |
| 0x37 | . | 0x38 | / |

### Decoding Script

```python
import subprocess

# USB HID Usage IDs → characters
hid_map = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e', 0x09: 'f',
    0x0a: 'g', 0x0b: 'h', 0x0c: 'i', 0x0d: 'j', 0x0e: 'k', 0x0f: 'l',
    0x10: 'm', 0x11: 'n', 0x12: 'o', 0x13: 'p', 0x14: 'q', 0x15: 'r',
    0x16: 's', 0x17: 't', 0x18: 'u', 0x19: 'v', 0x1a: 'w', 0x1b: 'x',
    0x1c: 'y', 0x1d: 'z',
    0x1e: '1', 0x1f: '2', 0x20: '3', 0x21: '4', 0x22: '5', 0x23: '6',
    0x24: '7', 0x25: '8', 0x26: '9', 0x27: '0',
    0x28: '\n', 0x2a: '\b', 0x2b: '\t', 0x2c: ' ',
    0x2d: '-', 0x2e: '=', 0x2f: '[', 0x30: ']', 0x31: '\\',
    0x33: ';', 0x34: "'", 0x35: '`', 0x36: ',', 0x37: '.', 0x38: '/',
}

result = subprocess.run(
    ['tshark', '-r', '39pa2x.pcapng', '-Y', 'udp.dstport == 31337',
     '-T', 'fields', '-e', 'data'],
    capture_output=True, text=True
)
lines = result.stdout.strip().split('\n')

# Extract key presses (skip release packets where keycode = 0)
keystrokes = []
for line in lines:
    payload = bytes.fromhex(line)[3:]   # skip 'HID' prefix
    modifier = payload[0]
    keycode = payload[2]

    if keycode == 0:
        continue                        # key release — skip

    shift = (modifier & 0x02) or (modifier & 0x20)
    key = hid_map.get(keycode, f'<{keycode:02x}>')

    # Apply shift
    if shift and key.isalpha():
        key = key.upper()
    elif shift:
        shift_map = {
            '1': '!', '2': '@', '3': '#', '4': '$', '5': '%',
            '6': '^', '7': '&', '8': '*', '9': '(', '0': ')',
            '-': '_', '=': '+', '[': '{', ']': '}', '\\': '|',
            ';': ':', "'": '"', '`': '~', ',': '<', '.': '>',
            '/': '?',
        }
        key = shift_map.get(key, key)

    keystrokes.append(key)

raw_text = ''.join(keystrokes)
```

### Raw Keystrokes

Running the decoder produces the following sequence:

```
note: fake 0xV01D{http_user_agent_is_bait}\nflag=0xV01D{hid_backspacx\x08es_are_evidence}\n
```

Notice the `\x08` (backspace) character inserted between `x` and `e`. This is where the hint **"not entered as cleanly"** comes from — the operator made a typo and corrected it.

### Simulating the Typing (Applying Backspaces)

To get the final intended text, we replay the keystrokes on a buffer, popping the last character whenever we encounter a backspace:

```python
result = []
for c in keystrokes:
    if c == '\b':
        if result:
            result.pop()
    else:
        result.append(c)

final_text = ''.join(result)
```

**Output:**
```
note: fake 0xV01D{http_user_agent_is_bait}
flag=0xV01D{hid_backspaces_are_evidence}
```

---

## The Flag

```
0xV01D{hid_backspaces_are_evidence}
```

---

## Key Takeaways

1. **Always check every stream.** The decoy flag in the HTTP User-Agent field was intentionally placed to distract solvers who only look for the first `0xV01D{...}` pattern.

2. **Read the hints carefully.** The description says *"The final text was not entered as cleanly as the first pass suggests"* — this directly points to backspace corrections in the HID keyboard data.

3. **HID keyboard forensics is common.** USB HID packet analysis appears frequently in CTF forensics challenges. Understanding the 8-byte report structure and the HID Usage Table is essential.

4. **Port 31337 = leetspeak for "elite".** Seeing this port is a strong indicator of custom/CTF-related traffic rather than standard protocol communication.
