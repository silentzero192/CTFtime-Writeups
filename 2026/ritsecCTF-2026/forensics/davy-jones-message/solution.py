#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import socket
import struct
import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import dpkt
import numpy as np


FLAG = "RS{REDACTED}"
POINTCLOUD_SOURCE = "10.42.0.10"
POINTCLOUD_WRITER = b"\x00\x00\x14\x03"


@dataclass
class FragmentBuffer:
    parts: dict[int, bytes] = field(default_factory=dict)
    total_length: int | None = None

    def add(self, offset: int, payload: bytes, more_fragments: bool) -> None:
        self.parts[offset] = payload
        if not more_fragments:
            self.total_length = offset + len(payload)

    def is_complete(self) -> bool:
        if self.total_length is None:
            return False

        offset = 0
        while offset < self.total_length:
            chunk = self.parts.get(offset)
            if chunk is None:
                return False
            offset += len(chunk)
        return True

    def build(self) -> bytes:
        return b"".join(self.parts[offset] for offset in sorted(self.parts))


@dataclass
class RtpsSample:
    sample_size: int
    fragment_size: int
    fragments: dict[int, bytes] = field(default_factory=dict)

    def add_fragment_block(
        self,
        starting_fragment: int,
        fragments_in_submessage: int,
        payload: bytes,
    ) -> None:
        for index in range(fragments_in_submessage):
            fragment_number = starting_fragment + index
            start = index * self.fragment_size
            end = start + self.fragment_size
            chunk = payload[start:end]
            if chunk:
                self.fragments[fragment_number] = chunk

    def is_complete(self) -> bool:
        total_fragments = (self.sample_size + self.fragment_size - 1) // self.fragment_size
        return all(fragment in self.fragments for fragment in range(1, total_fragments + 1))

    def build(self) -> bytes:
        total_fragments = (self.sample_size + self.fragment_size - 1) // self.fragment_size
        data = b"".join(self.fragments[fragment] for fragment in range(1, total_fragments + 1))
        return data[: self.sample_size]


@dataclass
class PointField:
    name: str
    offset: int
    datatype: int
    count: int


@dataclass
class PointCloud2:
    stamp_sec: int
    stamp_nsec: int
    frame_id: str
    height: int
    width: int
    fields: list[PointField]
    is_bigendian: bool
    point_step: int
    row_step: int
    data: bytes
    is_dense: bool


class CdrReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 4  # skip CDR encapsulation header

    def align(self, boundary: int) -> None:
        self.offset = (self.offset + boundary - 1) & ~(boundary - 1)

    def read_u8(self) -> int:
        value = self.data[self.offset]
        self.offset += 1
        return value

    def read_u32(self) -> int:
        self.align(4)
        value = struct.unpack_from("<I", self.data, self.offset)[0]
        self.offset += 4
        return value

    def read_string(self) -> str:
        length = self.read_u32()
        raw = self.data[self.offset : self.offset + length]
        self.offset += length
        self.align(4)
        return raw.rstrip(b"\x00").decode("ascii", errors="replace")


def ip_to_str(raw_ip: bytes) -> str:
    return socket.inet_ntoa(raw_ip)


def iter_reassembled_udp_payloads(pcap_path: Path):
    warnings.filterwarnings("ignore", message="IP.off is deprecated")

    ip_fragments: dict[tuple[bytes, bytes, int, int], FragmentBuffer] = {}

    with pcap_path.open("rb") as handle:
        for frame_number, (_, packet) in enumerate(dpkt.pcap.Reader(handle), start=1):
            ethernet = dpkt.ethernet.Ethernet(packet)
            if not isinstance(ethernet.data, dpkt.ip.IP):
                continue

            ip = ethernet.data
            fragment_offset = (ip.off & dpkt.ip.IP_OFFMASK) * 8
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_key = (ip.src, ip.dst, ip.p, ip.id)

            if fragment_offset or more_fragments:
                buffer = ip_fragments.setdefault(fragment_key, FragmentBuffer())
                buffer.add(fragment_offset, bytes(ip.data), more_fragments)
                if not buffer.is_complete():
                    continue

                payload = buffer.build()
                del ip_fragments[fragment_key]
                if ip.p != dpkt.ip.IP_PROTO_UDP:
                    continue
                udp = dpkt.udp.UDP(payload)
            else:
                if not isinstance(ip.data, dpkt.udp.UDP):
                    continue
                udp = ip.data

            yield frame_number, ip_to_str(ip.src), ip_to_str(ip.dst), udp


def iter_rtps_submessages(payload: bytes):
    if not payload.startswith(b"RTPS") or len(payload) < 20:
        return

    offset = 20
    while offset + 4 <= len(payload):
        submessage_id = payload[offset]
        flags = payload[offset + 1]
        little_endian = bool(flags & 0x01)
        length = int.from_bytes(
            payload[offset + 2 : offset + 4],
            "little" if little_endian else "big",
        )

        body_start = offset + 4
        body_end = body_start + length if length else len(payload)
        if body_end > len(payload):
            break

        yield submessage_id, flags, payload[body_start:body_end]
        offset = body_end


def reassemble_pointcloud_samples(pcap_path: Path) -> dict[int, bytes]:
    samples: dict[int, RtpsSample] = {}

    for _, src, _, udp in iter_reassembled_udp_payloads(pcap_path):
        if src != POINTCLOUD_SOURCE:
            continue

        payload = bytes(udp.data)
        for submessage_id, _, body in iter_rtps_submessages(payload):
            if submessage_id != 0x16 or len(body) < 32:
                continue

            writer_entity_id = body[8:12]
            if writer_entity_id != POINTCLOUD_WRITER:
                continue

            writer_seq = struct.unpack_from("<I", body, 16)[0]
            fragment_start = struct.unpack_from("<I", body, 20)[0]
            fragments_in_submessage = struct.unpack_from("<H", body, 24)[0]
            fragment_size = struct.unpack_from("<H", body, 26)[0]
            sample_size = struct.unpack_from("<I", body, 28)[0]
            fragment_payload = body[32:]

            sample = samples.setdefault(writer_seq, RtpsSample(sample_size, fragment_size))
            sample.add_fragment_block(fragment_start, fragments_in_submessage, fragment_payload)

    return {
        sequence_number: sample.build()
        for sequence_number, sample in samples.items()
        if sample.is_complete()
    }


def parse_pointcloud2(sample: bytes) -> PointCloud2:
    reader = CdrReader(sample)

    stamp_sec = reader.read_u32()
    stamp_nsec = reader.read_u32()
    frame_id = reader.read_string()
    height = reader.read_u32()
    width = reader.read_u32()

    fields_count = reader.read_u32()
    fields: list[PointField] = []
    for _ in range(fields_count):
        name = reader.read_string()
        offset = reader.read_u32()
        datatype = reader.read_u8()
        reader.align(4)
        count = reader.read_u32()
        fields.append(PointField(name=name, offset=offset, datatype=datatype, count=count))

    is_bigendian = bool(reader.read_u8())
    reader.align(4)
    point_step = reader.read_u32()
    row_step = reader.read_u32()
    data_length = reader.read_u32()
    data = reader.data[reader.offset : reader.offset + data_length]
    reader.offset += data_length
    is_dense = bool(reader.read_u8()) if reader.offset < len(reader.data) else False

    return PointCloud2(
        stamp_sec=stamp_sec,
        stamp_nsec=stamp_nsec,
        frame_id=frame_id,
        height=height,
        width=width,
        fields=fields,
        is_bigendian=is_bigendian,
        point_step=point_step,
        row_step=row_step,
        data=data,
        is_dense=is_dense,
    )


def pointcloud_to_arrays(pointcloud: PointCloud2):
    points = np.frombuffer(pointcloud.data, dtype="<f4").reshape(-1, pointcloud.point_step // 4)
    xyz = points[:, :3]
    rgb_as_uint32 = points[:, 3].copy().view("<u4")
    colors = np.stack(
        [
            ((rgb_as_uint32 >> 16) & 0xFF),
            ((rgb_as_uint32 >> 8) & 0xFF),
            (rgb_as_uint32 & 0xFF),
        ],
        axis=1,
    ).astype(np.float32) / 255.0

    finite = np.isfinite(xyz).all(axis=1)
    return xyz[finite], colors[finite]


def render_projection(
    x: np.ndarray,
    y: np.ndarray,
    colors: np.ndarray,
    output_path: Path,
    title: str,
    point_size: float = 1.0,
    figsize: tuple[float, float] = (8.0, 8.0),
) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    figure = plt.figure(figsize=figsize, dpi=200)
    axis = figure.add_subplot(111)
    axis.scatter(x, y, s=point_size, c=colors)
    axis.set_aspect("equal", adjustable="box")
    axis.set_title(title)
    figure.tight_layout()
    figure.savefig(output_path)
    plt.close(figure)


def render_flag_crop(xyz: np.ndarray, colors: np.ndarray, output_path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    yellow_mask = (colors[:, 0] > 0.8) & (colors[:, 1] > 0.7) & (colors[:, 2] < 0.3)
    flag_points = xyz[yellow_mask]
    flag_colors = colors[yellow_mask]

    figure = plt.figure(figsize=(16, 4), dpi=300)
    axis = figure.add_subplot(111)
    axis.scatter(flag_points[:, 0], flag_points[:, 2], s=8, c=flag_colors)
    axis.set_xlim(flag_points[:, 0].min() - 1, flag_points[:, 0].max() + 1)
    axis.set_ylim(flag_points[:, 2].min() - 1, flag_points[:, 2].max() + 1)
    axis.axis("off")
    figure.tight_layout(pad=0)
    figure.savefig(output_path, bbox_inches="tight", pad_inches=0)
    plt.close(figure)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recover the flag from the ROS2/DDS point cloud stored in the PCAP."
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        default="davy_jones_message.pcap",
        help="Path to the challenge PCAP.",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=1,
        help="Point cloud sample number to render. Default: 1",
    )
    parser.add_argument(
        "--output-dir",
        default="out",
        help="Directory for rendered output images. Default: out",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str((output_dir / ".mplconfig").resolve()))

    pcap_path = Path(args.pcap)
    samples = reassemble_pointcloud_samples(pcap_path)
    if not samples:
        raise SystemExit("No complete PointCloud2 samples were recovered from the PCAP.")

    if args.sample not in samples:
        available = f"{min(samples)}..{max(samples)}"
        raise SystemExit(f"Sample {args.sample} is unavailable. Recovered samples: {available}")

    pointcloud = parse_pointcloud2(samples[args.sample])
    xyz, colors = pointcloud_to_arrays(pointcloud)

    xy_path = output_dir / "flag_xy.png"
    xz_path = output_dir / "flag_xz.png"
    yz_path = output_dir / "flag_yz.png"
    crop_path = output_dir / "flag_crop.png"

    render_projection(xyz[:, 0], xyz[:, 1], colors, xy_path, "XY Projection")
    render_projection(xyz[:, 0], xyz[:, 2], colors, xz_path, "XZ Projection")
    render_projection(xyz[:, 1], xyz[:, 2], colors, yz_path, "YZ Projection")
    render_flag_crop(xyz, colors, crop_path)

    field_names = ", ".join(field.name.rstrip("\x00") for field in pointcloud.fields)

    print(f"[+] Reassembled {len(samples)} complete point cloud samples from {pcap_path}")
    print(
        "[+] Parsed PointCloud2 sample "
        f"{args.sample}: frame_id={pointcloud.frame_id!r}, "
        f"width={pointcloud.width}, point_step={pointcloud.point_step}, fields=[{field_names}]"
    )
    print(f"[+] Saved projections to {xy_path}, {xz_path}, {yz_path}")
    print(f"[+] Saved focused flag crop to {crop_path}")
    print(f"[+] Flag: {FLAG}")


if __name__ == "__main__":
    main()
