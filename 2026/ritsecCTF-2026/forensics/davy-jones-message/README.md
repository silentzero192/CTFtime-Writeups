# Davy Jones Message

## Challenge Info

- **Name:** `davy jones message`
- **Description:** `When sailors get lost, sometimes they will put a message in a bottle and set it off to sea in search of help. You sailor, have come across one of these bottles. Only thing is- it's broken. Something might be hidden here, if you can figure it out...`

## Files

- `davy_jones_message.pcap`
- `solution.py`

## TL;DR

The PCAP is not a normal file transfer at all. It contains ROS2 / DDS traffic using RTPS. The interesting stream is a fragmented `sensor_msgs/msg/PointCloud2` message coming from the `vehicle_sensor` node. Once the IPv4 fragments and RTPS `DATA_FRAG` pieces are reassembled, projecting the point cloud on the **x-z** plane reveals the flag text directly.

## Step 1: Basic Triage

The challenge directory only contained a single PCAP:

```bash
ls -lah
```

That showed:

```text
davy_jones_message.pcap
```

Quick protocol triage with `tshark`/`capinfos` showed:

- ~13k packets
- only two IPv4 hosts: `10.42.0.10` and `10.42.0.11`
- traffic identified as **RTPS**
- vendor ID matching **Cyclone DDS**

That is a very strong hint that this is ROS2 middleware traffic rather than HTTP/FTP/SMB or a classic file exfiltration.

## Step 2: Identify the ROS2 Context

Looking at the RTPS discovery messages exposed two node names:

- `vehicle_sensor`
- `computer_control`

So instead of searching for a transferred image or archive, the better direction was:

1. recover the published ROS2 messages
2. identify the interesting topic payload
3. render it into a human-readable form

## Step 3: Notice the Large Fragmented Stream

The main suspicious stream was:

- from `10.42.0.10`
- RTPS `DATA_FRAG`
- sample size `36628`
- repeated hundreds of times

This indicated a large ROS2 payload being fragmented twice:

- first by RTPS (`DATA_FRAG`)
- then again at the IPv4 layer

So simply carving UDP payloads was not enough. The solve path needed:

1. IPv4 fragment reassembly
2. RTPS `DATA_FRAG` sample reassembly

## Step 4: Reassemble IPv4 Fragments

Some RTPS packets were themselves spread across many IPv4 fragments. The script reassembles them by:

- grouping on `(src, dst, protocol, ip.id)`
- tracking fragment offsets
- waiting until the final fragment arrives
- stitching the payload back together into the original UDP datagram

Once that is done, the RTPS packet becomes parseable.

## Step 5: Reassemble RTPS `DATA_FRAG`

Inside the reassembled UDP payload, the script iterates RTPS submessages and looks for:

- submessage ID `0x16` = `DATA_FRAG`
- writer entity ID `0x00001403`
- source IP `10.42.0.10`

Each `DATA_FRAG` block provides:

- writer sequence number
- starting fragment number
- fragment count in this submessage
- RTPS fragment size
- total sample size

The script stores those chunks until every fragment for a given sequence number is present, then concatenates them into the full ROS2 sample.

## Step 6: Confirm the Message Type

The first recovered sample begins with a CDR header and a ROS2-style serialized structure. Parsing the message shows:

- `frame_id = "wf"`
- `height = 1`
- `width = 2281`
- fields:
  - `x`
  - `y`
  - `z`
  - `rgb`
- `point_step = 16`

That is a dead giveaway for:

`sensor_msgs/msg/PointCloud2`

So the “broken bottle” clue was effectively pointing at a fragmented 3D point cloud.

## Step 7: Render the Point Cloud

After decoding the point records as:

- `x: float32`
- `y: float32`
- `z: float32`
- `rgb: packed float32`

the interesting move is to render simple orthographic projections:

- `x-y`
- `x-z`
- `y-z`

The crucial one is the **x-z projection**. That view clearly spells out the flag in yellow points above the rest of the scene.

## Recovered Flag

```text
RS{D4vy_J0nes_Sp3aks_1n_5il3nce}
```

## Solution Script

Run:

```bash
python3 solution.py
```

What it does:

1. reads the PCAP
2. reassembles IPv4 fragments
3. extracts RTPS packets
4. rebuilds complete `DATA_FRAG` samples
5. parses the first complete `PointCloud2`
6. renders:
   - `out/flag_xy.png`
   - `out/flag_xz.png`
   - `out/flag_yz.png`
   - `out/flag_crop.png`
7. prints the recovered flag

Example output:

```text
[+] Reassembled 316 complete point cloud samples from davy_jones_message.pcap
[+] Parsed PointCloud2 sample 1: frame_id='wf', width=2281, point_step=16, fields=[x, y, z, rgb]
[+] Saved projections to out/flag_xy.png, out/flag_xz.png, out/flag_yz.png
[+] Saved focused flag crop to out/flag_crop.png
[+] Flag: RS{D4vy_J0nes_Sp3aks_1n_5il3nce}
```

## Why This Works

The challenge hides the flag in a visualization artifact, not in plain text:

- no direct flag string exists in the PCAP
- the traffic is middleware chatter from a robotics stack
- the useful content is embedded in a sensor message
- the flag only becomes obvious after reconstructing and plotting the 3D data

So the full solve path is:

`PCAP -> IPv4 fragments -> RTPS DATA_FRAG -> PointCloud2 -> x-z projection -> flag`

## Notes

- The node names `vehicle_sensor` and `computer_control` are useful breadcrumbs but not the flag themselves.
- The large fragmented ROS2 stream is the important artifact.
- The flag is visible from the very first complete point cloud sample, so no multi-frame accumulation is required.
