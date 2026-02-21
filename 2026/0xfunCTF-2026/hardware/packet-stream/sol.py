#!/usr/bin/env python3
import numpy as np
from pathlib import Path
from PIL import Image


def lfsr_mask_byte(state: int) -> tuple[int, int]:
    """
    DisplayPort-style 16-bit self-synchronizing scrambler variant that works here:
      - right-shift LFSR
      - feedback taps correspond to x^16 + x^5 + x^4 + x^3 + 1  (bit0,3,4,5)
      - output bit = bit15 (MSB) BEFORE shift
      - pack output bits MSB-first into each mask byte

    Returns: (new_state, mask_byte)
    """
    mask = 0
    for i in range(8):
        out_bit = (state >> 15) & 1
        fb = ((state >> 0) ^ (state >> 3) ^ (state >> 4) ^ (state >> 5)) & 1
        state = (state >> 1) | (fb << 15)
        mask |= out_bit << (7 - i)
    return state, mask


def main() -> None:
    blob = Path("signal.bin").read_bytes()
    zip_off = blob.find(b"PK\x03\x04")
    if zip_off < 0:
        raise SystemExit("Could not locate embedded ZIP (PK\\x03\\x04).")

    prefix = blob[:zip_off]
    if not prefix.startswith(b"dp_signal") or len(prefix) != 2_100_020:
        raise SystemExit(f"Unexpected prefix header/length: starts={prefix[:16]!r} len={len(prefix)}")

    payload = prefix[20:]  # 2,100,000 bytes
    if len(payload) != 2_100_000:
        raise SystemExit(f"Unexpected payload length: {len(payload)}")

    # Bytes -> bitstream (little-endian within each byte) -> 10-bit words.
    b = np.frombuffer(payload, dtype=np.uint8)
    bits = np.unpackbits(b, bitorder="little")
    if bits.size % 10 != 0:
        raise SystemExit("Bitstream length not divisible by 10.")
    words10 = bits.reshape(-1, 10).dot(1 << np.arange(9, -1, -1)).astype(np.uint16)

    # 8b/10b decode
    from encdec8b10b import EncDec8B10B

    codec = EncDec8B10B()
    ctrl = np.empty(words10.size, dtype=np.uint8)
    data = np.empty(words10.size, dtype=np.uint8)
    for i, w in enumerate(words10):
        c, d = codec.dec_8b10b(int(w))
        ctrl[i] = c
        data[i] = d

    # Time-major: (525 rows, 800 cols, 4 lanes)
    ctrl = ctrl.reshape(525, 800, 4)
    data = data.reshape(525, 800, 4)

    ctrl_any = ctrl[:, :, 0].astype(bool)
    row_ctrl_counts = ctrl_any.sum(axis=1)
    active_rows = np.where(row_ctrl_counts == 19)[0]
    if active_rows.size != 480:
        raise SystemExit(f"Unexpected active row count: {active_rows.size}")

    # TU start marker column (control byte 0xFB), then payload begins 4 columns later.
    lane0 = data[:, :, 0]
    cand = np.where(
        (ctrl_any[active_rows].all(axis=0))
        & (lane0[active_rows].min(axis=0) == 0xFB)
        & (lane0[active_rows].max(axis=0) == 0xFB)
    )[0]
    if cand.size == 0:
        raise SystemExit("Could not locate TU start marker (control 0xFB column).")
    tu0 = int(cand[0])
    payload_start = tu0 + 4

    # Descramble: XOR mask for each data byte; reset on SR (control 0x1C).
    state = 0xFFFF
    for y in range(525):
        for x in range(800):
            if ctrl_any[y, x] and lane0[y, x] == 0x1C:
                state = 0xFFFF
                continue
            if ctrl_any[y, x]:
                continue
            state, mask = lfsr_mask_byte(state)
            data[y, x, :] ^= mask

    # Extract 640x480 RGB pixels:
    frame_rows = []
    for y in active_rows:
        ticks = np.concatenate(
            [data[y, payload_start + blk * 64 : payload_start + blk * 64 + 60, :] for blk in range(8)],
            axis=0,
        )  # 480 x 4
        frame_rows.append(ticks.reshape(-1))

    frame = np.stack(frame_rows, axis=0).astype(np.uint8)  # 480 x 1920
    img = frame.reshape(480, 640, 3)

    out_path = Path("out.png")
    Image.fromarray(img, "RGB").save(out_path)
    print(f"Wrote {out_path} (read the bottom caption for the flag).")


if __name__ == "__main__":
    main()
