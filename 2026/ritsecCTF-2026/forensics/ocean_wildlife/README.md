# Ocean Wildlife

## Challenge Info

- **Name:** `ocean wildlife`
- **Category:** `Forensics`
- **Description:** `You have recieved a message in a bottle, saying something about the strange behavior of sea creatures. I wonder what that could be about?`
- **Flag format:** `RS{...}`

## Files Provided

```text
metadata.yaml
mystery_message_0.db3
```

At first glance, the interesting file is `mystery_message_0.db3`, which is a SQLite database. The companion `metadata.yaml` suggests it belongs to some recorded message/session rather than being a normal application database.

## Initial Triage

### 1. Identify the files

```bash
file mystery_message_0.db3
sed -n '1,220p' metadata.yaml
```

Relevant results:

```text
mystery_message_0.db3: SQLite 3.x database
```

`metadata.yaml` shows that this is a `rosbag2` recording using SQLite storage:

```yaml
rosbag2_bagfile_information:
  storage_identifier: sqlite3
```

It also reveals the recorded topics:

- `/draw_commands`
- `/turtle1/pose`
- `/turtle1/color_sensor`
- `/rosout`
- `/parameter_events`

That is a big clue. `turtle1` and `turtlesim` point to the ROS turtle simulator, which fits the challenge description about unusual sea-creature behavior.

## Understanding the Artifact

This challenge is a **ROS 2 bag** stored in SQLite format. ROS bags commonly contain recorded topic messages. In a `rosbag2` SQLite database, the two most useful tables are:

- `topics`: maps topic IDs to topic names/types
- `messages`: stores serialized message blobs

List the tables:

```bash
sqlite3 mystery_message_0.db3 ".tables"
```

Output:

```text
messages  metadata  schema  topics
```

Inspect the topics:

```bash
sqlite3 mystery_message_0.db3 "select id,name,type from topics order by id;"
```

Output:

```text
1|/turtle1/pose|turtlesim/msg/Pose
2|/turtle1/color_sensor|turtlesim/msg/Color
3|/rosout|rcl_interfaces/msg/Log
4|/parameter_events|rcl_interfaces/msg/ParameterEvent
5|/events/write_split|rosbag2_interfaces/msg/WriteSplitEvent
6|/draw_commands|std_msgs/msg/String
```

Message counts:

```bash
sqlite3 mystery_message_0.db3 "select topic_id,count(*) from messages group by topic_id order by topic_id;"
```

Output:

```text
1|552
2|552
3|15
4|1
6|284
```

The most interesting topics are:

- `/draw_commands`: likely custom drawing instructions
- `/rosout`: application log messages

## Solution Steps

### 1. Inspect the custom drawing commands

The `/draw_commands` topic contains `std_msgs/msg/String`, encoded in ROS 2 CDR format. Pulling a few samples shows JSON drawing commands:

```bash
sqlite3 mystery_message_0.db3 \
  "select timestamp,length(data),hex(data) from messages where topic_id=6 order by timestamp limit 8;"
```

Decoded content includes entries like:

```json
{"cmd": "teleport", "x": 1.044999999999999, "y": 5.845, "theta": 0.0}
{"cmd": "pen", "r": 255, "g": 255, "b": 255, "width": 3, "off": 0}
```

This shows the turtle is being moved around the canvas to draw text. The challenge description hints at sea creatures, and the presence of `turtle1` confirms that the bag captured a turtlesim-based drawing session.

### 2. Inspect the ROS log topic

The cleaner and more reliable source is `/rosout`, which stores log messages from the node doing the drawing.

Get the latest log messages:

```bash
sqlite3 mystery_message_0.db3 \
  "select rowid,timestamp,length(data),hex(data) from messages where topic_id=3 order by timestamp desc limit 5;"
```

The final `/rosout` message contains this ASCII string inside the serialized log payload:

```text
Finished drawing: RS{f0ll0w_th3_5ea_Turtles}
```

One example row:

```text
1006|1774823550389444363|168|000100007EA8C9698CF03417140000000F000000647261775F746578745F6E6F646500002D00000046696E69736865642064726177696E673A2052537B66306C6C30775F7468335F3565615F547572746C65737D...
```

The important hex chunk is:

```text
46696E69736865642064726177696E673A2052537B66306C6C30775F7468335F3565615F547572746C65737D
```

Which decodes to the flag.

## Why This Worked

The challenge author recorded a ROS 2 turtlesim session in which a node published drawing commands to move a turtle around and draw text. The final flag was not hidden in an image file; it was exposed in the recorded ROS logs once the text drawing completed.

The solve chain was:

1. Recognize `metadata.yaml` + `.db3` as a `rosbag2` artifact.
2. Inspect topics and notice `turtlesim`, `/draw_commands`, and `/rosout`.
3. Extract readable strings and/or query the log topic directly.
4. Recover the final logged message containing the flag.

## Final Flag

```text
RS{f0ll0w_th3_5ea_Turtles}
```

## Notes

- The challenge can be solved very quickly with `strings`, but understanding the bag structure makes the writeup more defensible.
- If `strings` had not revealed the flag directly, the next step would have been to properly deserialize ROS 2 CDR messages from `/rosout` and `/draw_commands`.
- The hint in the description about sea creatures strongly nudges toward `turtlesim`, which is the key contextual clue.
