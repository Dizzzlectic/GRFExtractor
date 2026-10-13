"""Decode the supported GRF version 3 archive key block without the client.

The supported client derives CHAM-128/128 key and IV from a fixed SHA-256 input.
CHAM uses 80 rounds and big-endian words. See docs/format.md.
"""

import hashlib
import struct

import xxhash


FOOTER_HASH_INPUT = b"uf8E8qAwHthrLxiS"
MASK32 = 0xffffffff


def rotate_left(value, count):
    return ((value << count) | (value >> (32 - count))) & MASK32


def cham_keys(key):
    words = struct.unpack(">4I", key)
    keys = [0] * 8
    for index, word in enumerate(words):
        keys[index] = word ^ rotate_left(word, 1) ^ rotate_left(word, 8)
        keys[(index + 4) ^ 1] = word ^ rotate_left(word, 1) ^ rotate_left(word, 11)
    return keys


def cham_decrypt(block, keys):
    words = list(struct.unpack(">4I", block))
    for round_index in range(79, -1, -1):
        index = round_index % 4
        right_rotation = 1 if round_index & 1 else 8
        neighbor_rotation = 8 if round_index & 1 else 1
        a = rotate_left(words[index], 32 - right_rotation)
        b = rotate_left(words[(index + 1) % 4], neighbor_rotation) ^ keys[round_index % 8]
        words[index] = ((a - b) & MASK32) ^ round_index
    return struct.pack(">4I", *words)


def decode_footer(raw):
    if len(raw) < 20 or raw[:4] != b"\x01\x01\x00\x00":
        raise ValueError("Unsupported or truncated GRF key block")
    body_length, checksum = struct.unpack_from("<II", raw, 12)
    if not body_length or body_length % 64 or len(raw) != 20 + body_length:
        raise ValueError("GRF key-block size mismatch")
    digest = hashlib.sha256(FOOTER_HASH_INPUT).digest()
    keys = cham_keys(digest[:16])
    previous = digest[16:]
    decoded = bytearray()
    for offset in range(20, len(raw), 16):
        block = raw[offset:offset + 16]
        decoded.extend(a ^ b for a, b in zip(cham_decrypt(block, keys), previous))
        previous = block
    if xxhash.xxh32_intdigest(decoded) != checksum:
        raise ValueError("GRF key-block checksum mismatch")
    records = {}
    for offset in range(0, len(decoded), 64):
        key_id = struct.unpack_from("<I", decoded, offset)[0]
        if not 0 < key_id <= 0xffff or key_id in records:
            raise ValueError("Invalid or duplicate GRF key-block record")
        records[key_id] = bytes(decoded[offset + 4:offset + 64])
    return records
