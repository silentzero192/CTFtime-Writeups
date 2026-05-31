#!/usr/bin/env python3
"""Solution script for "Duality in All Things" — greyCTF Quals 2026.

Extracts the flag from the SVM dual parameters by decoding the slack variables
embedded in the support vectors.
"""
from __future__ import annotations

import pickle
import sys

import numpy as np


def extract_flag(pkl_path: str = "svc_dual_params.pkl") -> str:
    with open(pkl_path, "rb") as f:
        model = pickle.load(f)

    sv = model.support_vectors_
    dc = model.dual_coef_[0]

    ys = np.sign(dc)

    w = (model.dual_coef_ @ model.support_vectors_)[0]
    b = model.intercept_[0]
    fx = sv @ w + b

    yfx = ys * fx
    slack = np.maximum(0, 1 - yfx)

    slack_neg = slack[0::2][:-1]
    slack_pos = slack[1::2][:-1]

    bit_neg = (slack_neg > 0.5).astype(int)
    bit_pos = (slack_pos > 0.6).astype(int)

    bits = []
    for i in range(len(bit_neg)):
        bits.append(int(bit_neg[i]))
        bits.append(int(bit_pos[i]))

    result = ""
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result += chr(byte)

    return result[result.index("grey{"):result.index("}") + 1]


if __name__ == "__main__":
    flag = extract_flag(sys.argv[1] if len(sys.argv) > 1 else "svc_dual_params.pkl")
    print(flag)
