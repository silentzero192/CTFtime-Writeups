#!/usr/bin/env python3

from struct import pack, unpack


KEY = b"tiny_encrypt_key"
EXPECTED = bytes.fromhex(
    "38755bcb44d2be5d969c5643ea980675"
    "4a4813e6d4e88e4f72708bffdc99f876"
    "c5c9"
)
DELTA = 0x9E3779B9


def to_u32_words(data: bytes) -> list[int]:
    return [unpack("<I", data[i : i + 4])[0] for i in range(0, len(data), 4)]


def tea_encrypt_block(block: bytes, key_words: list[int]) -> bytes:
    v0, v1 = unpack("<2I", block)
    total = 0

    for _ in range(32):
        total = (total + DELTA) & 0xFFFFFFFF
        v0 = (
            v0
            + (((v1 << 4) + key_words[0]) ^ (v1 + total) ^ ((v1 >> 5) + key_words[1]))
        ) & 0xFFFFFFFF
        v1 = (
            v1
            + (((v0 << 4) + key_words[2]) ^ (v0 + total) ^ ((v0 >> 5) + key_words[3]))
        ) & 0xFFFFFFFF

    return pack("<2I", v0, v1)


def tea_decrypt_block(block: bytes, key_words: list[int]) -> bytes:
    v0, v1 = unpack("<2I", block)
    total = (DELTA * 32) & 0xFFFFFFFF

    for _ in range(32):
        v1 = (
            v1
            - (((v0 << 4) + key_words[2]) ^ (v0 + total) ^ ((v0 >> 5) + key_words[3]))
        ) & 0xFFFFFFFF
        v0 = (
            v0
            - (((v1 << 4) + key_words[0]) ^ (v1 + total) ^ ((v1 >> 5) + key_words[1]))
        ) & 0xFFFFFFFF
        total = (total - DELTA) & 0xFFFFFFFF

    return pack("<2I", v0, v1)


def recover_flag() -> str:
    key_words = to_u32_words(KEY)

    # The comparison uses 34 bytes, but the first four full 8-byte blocks already
    # decrypt to the complete flag and its terminating zero padding.
    plaintext = b"".join(
        tea_decrypt_block(EXPECTED[i : i + 8], key_words) for i in range(0, 32, 8)
    )
    return plaintext.rstrip(b"\x00").decode()


def emulate_binary(candidate: bytes) -> bytes:
    key_words = to_u32_words(KEY)
    remainder = len(candidate) % 8
    total_len = len(candidate) + remainder

    # The binary allocates too little and then encrypts too many blocks. Modeling a
    # fresh zeroed chunk is enough to reproduce the observed ciphertext prefix.
    buf = bytearray(64)
    buf[: len(candidate)] = candidate

    for block_index in range(total_len >> 2):
        start = block_index * 8
        buf[start : start + 8] = tea_encrypt_block(bytes(buf[start : start + 8]), key_words)

    return bytes(buf[:total_len])


def main() -> None:
    flag = recover_flag()
    reproduced = emulate_binary(flag.encode())

    print(f"Flag: {flag}")
    print(f"Matches embedded ciphertext: {reproduced == EXPECTED}")
    print(f"Ciphertext: {reproduced.hex()}")


if __name__ == "__main__":
    main()
