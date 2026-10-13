#!/usr/bin/env python3
"""Inspect protected GRF headers without running the client (not body decryption)."""

import argparse
import json
from pathlib import Path
import struct

import xxhash
from Crypto.Cipher import AES

from ..archive import read_entries
from .threeway import decrypt_cfb96


AES_KEY = bytes.fromhex("56fd7e712f6d36f55ca599e67b18107a")
AES_IV = bytes.fromhex("4ce8a1ae45b321607e4f26a4bb140c96")
THREEWAY_KEY = bytes.fromhex("ad61aedabf203e1dfe1db72b")
THREEWAY_IV = bytes.fromhex("a095dfcfd04b74db027ede09")


def derive48(source):
    """Recover stable key material from a randomized native 64-byte key buffer."""
    if len(source) != 64:
        raise ValueError("Expected a 64-byte key buffer")
    return bytes(source[16 + index] ^ source[index % 6] ^ source[10 + index % 6]
                 for index in range(48))


def xxh128_native(data):
    # Windows x86 stores low64 followed by high64, both little endian.
    return xxhash.xxh3_128_intdigest(data).to_bytes(16, "little")


def decode_header(raw, filename):
    if len(raw) < 104 or raw[0] != 1:
        raise ValueError("Unsupported or truncated protected header")
    kind = raw[1]
    if kind == 0x71:
        descriptor = decrypt_cfb96(THREEWAY_KEY, THREEWAY_IV, raw[8:104])
    else:
        if kind == 1:
            iv = AES_IV
        elif kind == 2:
            iv = xxh128_native(filename)
        elif kind == 0x0f:
            iv = xxh128_native(raw[4:8])
        else:
            raise ValueError(f"Unsupported header type {kind:#x}")
        descriptor = AES.new(AES_KEY, AES.MODE_CBC, iv).decrypt(raw[8:104])
    if xxhash.xxh32_intdigest(descriptor) != struct.unpack_from("<I", raw, 4)[0]:
        raise ValueError("Protected header checksum mismatch")
    return raw[:8] + descriptor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--entry", required=True)
    args = parser.parse_args()
    requested = args.entry.lower().replace("\\", "/")
    matches = [entry for entry in read_entries(args.archive)
               if entry[0].decode("cp949").lower().replace("\\", "/") == requested]
    if len(matches) != 1 or matches[0][4] != 128:
        parser.error("Expected exactly one protected entry")
    name, _packed, _aligned, _real, _flags, offset = matches[0]
    with args.archive.open("rb") as source:
        source.seek(offset)
        header = decode_header(source.read(104), name)
    print(json.dumps({
        "name_hex": name.hex(), "decoded_header_hex": header.hex(),
        "header_type": header[1], "cipher_id": struct.unpack_from("<H", header, 8)[0],
        "compression": header[10], "padded_size": struct.unpack_from("<I", header, 12)[0],
        "compressed_size": struct.unpack_from("<I", header, 16)[0],
        "output_size": struct.unpack_from("<I", header, 20)[0],
        "output_xxh3_128": header[24:40].hex(),
        "field_40": struct.unpack_from("<I", header, 40)[0],
    }, indent=2))


if __name__ == "__main__":
    main()
