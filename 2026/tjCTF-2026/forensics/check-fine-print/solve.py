#!/usr/bin/env python3

from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent
    png_path = root / "logo.png"
    data = png_path.read_bytes()

    zip_magic = b"PK\x03\x04"
    zip_offset = data.index(zip_magic)
    zip_blob = data[zip_offset:]

    out_dir = root / "extracted"
    out_dir.mkdir(exist_ok=True)
    zip_path = out_dir / "hidden.zip"
    zip_path.write_bytes(zip_blob)

    import zipfile

    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(out_dir)
        names = sorted(name for name in zf.namelist() if name.endswith(".png"))

    bits = []
    for name in names:
        blob = (out_dir / name).read_bytes()
        bits.append("1" if blob[26] == 1 else "0")

    bitstring = "".join(bits)
    flag = bytes(int(bitstring[i : i + 8], 2) for i in range(0, len(bitstring), 8)).decode()
    print(flag)


if __name__ == "__main__":
    main()
