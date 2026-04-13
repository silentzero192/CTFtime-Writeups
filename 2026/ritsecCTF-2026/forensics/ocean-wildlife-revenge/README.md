# Ocean Wildlife Revenge

## Challenge Info

- Name: `ocean wildlife revenge`
- Category: `Forensics`
- Description: `See the first challenge`
- Flag format: `RS{...}`

## Files Provided

```text
metadata.yaml
mystery_message_0.db3
```

## Overview

This challenge is another ROS 2 bag stored in SQLite format, but unlike the first `ocean_wildlife` challenge it does **not** include the easy `/rosout` log leak containing the final message.

That means the intended solve path is to recover the drawing itself from the recorded `/draw_commands` topic and read the flag from the rendered output.

## Initial Triage

Start by identifying the files:

```bash
file mystery_message_0.db3
sed -n '1,220p' metadata.yaml
sqlite3 mystery_message_0.db3 ".tables"
sqlite3 mystery_message_0.db3 "select id,name,type from topics order by id;"
sqlite3 mystery_message_0.db3 "select topic_id,count(*) from messages group by topic_id order by topic_id;"
```

Important observations:

- `mystery_message_0.db3` is a SQLite database.
- `metadata.yaml` shows it is a `rosbag2` recording with SQLite storage.
- The topics are:
  - `/parameter_events`
  - `/turtle1/color_sensor`
  - `/turtle1/pose`
  - `/draw_commands`
- There is **no `/rosout` topic** in this revenge version.

That difference from the first challenge is the key clue: we cannot simply scrape logs for the flag anymore.

## Quick Clue From Strings

Running `strings` shows a large number of readable JSON objects:

```bash
strings -a mystery_message_0.db3 | rg 'teleport|pen|RS\{|draw'
```

This reveals many entries like:

```json
{"cmd": "pen", "r": 255, "g": 255, "b": 255, "width": 3, "off": 0}
{"cmd": "teleport", "x": 1.6949999999999994, "y": 6.67, "theta": 0.0}
```

So the bag clearly contains drawing instructions for `turtlesim`. However, unlike the first challenge, the flag is not printed directly in plain text. We need to reconstruct the drawing.

## Understanding The Data

The interesting topic is `/draw_commands`, whose message type is:

```text
std_msgs/msg/String
```

Inside the ROS 2 bag, each message is serialized using CDR encoding. For `std_msgs/msg/String`, the payload layout is simple:

1. 4-byte CDR encapsulation header
2. 4-byte little-endian string length
3. UTF-8 string bytes
4. trailing null byte

That means each message can be decoded with:

```python
length = struct.unpack("<I", blob[4:8])[0]
text = blob[8:8+length-1].decode()
```

Once decoded, the strings are JSON commands describing how the turtle moves:

- `{"cmd": "pen", ..., "off": 0}` means pen down
- `{"cmd": "pen", ..., "off": 1}` means pen up
- `{"cmd": "teleport", "x": ..., "y": ..., "theta": 0.0}` moves the turtle

When the pen is down, a line should be drawn from the previous position to the new position.

## Solve Strategy

The recovery process is:

1. Open the SQLite bag.
2. Read all messages for topic ID `4` (`/draw_commands`) in timestamp order.
3. Decode each `std_msgs/msg/String` payload from CDR.
4. Parse the JSON commands.
5. Simulate the turtle:
   - keep track of the current position
   - toggle drawing on `pen` commands
   - draw a line between consecutive `teleport` positions when the pen is down
6. Save the reconstructed drawing as an image.
7. Read the text from the output image.

## Reconstructing The Image

I wrote a small solver that renders the stroke data with Pillow.

Core logic:

```python
if command["cmd"] == "pen":
    pen_down = command["off"] == 0

if command["cmd"] == "teleport":
    if current is not None and pen_down:
        draw.line((current[0], current[1], x, y), fill=255, width=8)
    current = (x, y)
```

## Solver

The included [solution.py](/home/jilani/Desktop/ritsecCTF-2026/forensics/ocean-wildlife-revenge/solution.py) does the full recovery:

- extracts `/draw_commands`
- decodes the ROS 2 string messages
- renders the turtle drawing to `recovered_flag.png`
- prints the recovered flag

Run it with:

```bash
python3 solution.py
```

Expected output:

```text
Recovered 295 draw commands from mystery_message_0.db3
Rendered output image to recovered_flag.png
Flag: RS{W4tch1ng_r0b0t_turtl3s}
```

## Why This Challenge Is The "Revenge"

The first `ocean_wildlife` bag exposed the answer in `/rosout`, so `strings` or a direct log query was enough.

This revenge version removes the logs and leaves only the turtle drawing instructions, so the solve requires actual reconstruction instead of simple text extraction.

That makes it a nice escalation of the same idea:

- first challenge: inspect logs
- revenge challenge: reconstruct the hidden text from the drawing stream

## Final Flag

```text
RS{W4tch1ng_r0b0t_turtl3s}
```
