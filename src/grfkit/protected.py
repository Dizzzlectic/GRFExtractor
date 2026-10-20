# SPDX-License-Identifier: GPL-3.0-or-later
# Adapted from Flux159/roBrowserLegacy-RemoteClient-Rust protected-GRF codec
# revision a210fee29fef73eacf8a52ee3a4e79d59a5cf5cf (see NOTICE).
"""Checked, reversible kRO protected-GRF entry and archive-key codecs.

Format and cipher operations follow gruf's native protected GRF decoder and
its independently generated synthetic vectors. Names are the original encoded
archive bytes: decoding/re-encoding their display text changes cryptographic IVs.
"""
from __future__ import annotations

import hashlib
import secrets
import struct
import zlib

import lz4.block
import xxhash
from Crypto.Cipher import AES

MAX_OUTPUT_SIZE = 256 * 1024 * 1024
_MASK = 0xFFFFFFFF
_AES_KEY = bytes.fromhex("56fd7e712f6d36f55ca599e67b18107a")
_AES_IV = bytes.fromhex("4ce8a1ae45b321607e4f26a4bb140c96")
_THREEWAY_KEY = bytes.fromhex("ad61aedabf203e1dfe1db72b")
_THREEWAY_IV = bytes.fromhex("a095dfcfd04b74db027ede09")
_KEY_DIGEST = hashlib.sha256(b"uf8E8qAwHthrLxiS").digest()


def _hash(data: bytes, seed: int = 0) -> bytes:
    return xxhash.xxh3_128_intdigest(data, seed=seed).to_bytes(16, "little")


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _rol(value: int, count: int) -> int:
    count &= 31
    value &= _MASK
    return ((value << count) | (value >> ((32 - count) & 31))) & _MASK


def _cham_keys(key: bytes) -> list[int]:
    keys = [0] * 8
    for i, value in enumerate(struct.unpack(">4I", key)):
        keys[i] = value ^ _rol(value, 1) ^ _rol(value, 8)
        keys[(i + 4) ^ 1] = value ^ _rol(value, 1) ^ _rol(value, 11)
    return keys


def _cham_block(block: bytes, keys: list[int], decrypt: bool = False) -> bytes:
    words = list(struct.unpack(">4I", block))
    for r in (range(79, -1, -1) if decrypt else range(80)):
        i = r % 4
        neighbor = _rol(words[(i + 1) % 4], 8 if r & 1 else 1) ^ keys[r % 8]
        rotation = 1 if r & 1 else 8
        if decrypt:
            words[i] = ((_rol(words[i], 32 - rotation) - neighbor) & _MASK) ^ r
        else:
            words[i] = _rol(((words[i] ^ r) + neighbor) & _MASK, rotation)
    return struct.pack(">4I", *words)


def _cham_cbc(data: bytes, key: bytes, iv: bytes, decrypt: bool = False) -> bytes:
    if len(data) % 16:
        raise ValueError("CHAM input is not block aligned")
    keys = _cham_keys(key)
    output = bytearray()
    previous = iv
    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        if decrypt:
            output.extend(_xor(_cham_block(block, keys, True), previous))
            previous = block
        else:
            previous = _cham_block(_xor(block, previous), keys)
            output.extend(previous)
    return bytes(output)


def _theta(a: int, b: int, c: int) -> tuple[int, int, int]:
    mix = _rol(a ^ b ^ c, 16) ^ _rol(a ^ b ^ c, 8)
    u = ((a << 24) ^ (c >> 8) ^ (b << 8) ^ (a >> 24)) & _MASK
    v = ((b << 24) ^ (a >> 8) ^ (c << 8) ^ (b >> 24)) & _MASK
    return ((a ^ mix ^ u) & _MASK, (b ^ mix ^ v) & _MASK,
            (c ^ mix ^ (u >> 16) ^ (v << 16)) & _MASK)


def _threeway_encrypt(key: bytes, block: bytes) -> bytes:
    k0, k1, k2 = struct.unpack(">3I", key)
    a, b, c = struct.unpack(">3I", block)
    rc = 0x0B0B
    for _ in range(11):
        a, b, c = _theta(a ^ k0 ^ (rc << 16), b ^ k1, c ^ k2 ^ rc)
        u, v = _rol(a, 22), _rol(c, 1)
        a, b, c = (_rol(u ^ (b | ~v), 1), (b ^ (v | ~u)) & _MASK,
                   _rol(v ^ (u | ~b), 22))
        rc <<= 1
        if rc & 0x10000:
            rc ^= 0x11011
    return struct.pack(">3I", *_theta(a ^ k0 ^ (rc << 16), b ^ k1, c ^ k2 ^ rc))


def _cfb(data: bytes, encrypt_block, iv: bytes, block_size: int,
         decrypt: bool = False) -> bytes:
    output = bytearray()
    previous = iv
    for off in range(0, len(data), block_size):
        block = data[off:off + block_size]
        transformed = _xor(block, encrypt_block(previous))
        output.extend(transformed)
        previous = block if decrypt else transformed
    return bytes(output)


def _idea_keys(key: bytes) -> list[int]:
    value = int.from_bytes(key, "big")
    result = []
    for i in range(52):
        if i and i % 8 == 0:
            value = ((value << 25) | (value >> 103)) & ((1 << 128) - 1)
        result.append((value >> (112 - 16 * (i % 8))) & 0xFFFF)
    return result


def _idea_mul(a: int, b: int) -> int:
    return (((a or 65536) * (b or 65536)) % 65537) & 0xFFFF


def _idea_encrypt(block: bytes, keys: list[int]) -> bytes:
    a, b, c, d = struct.unpack(">4H", block)
    for i in range(0, 48, 6):
        a, b, c, d = (_idea_mul(a, keys[i]), (b + keys[i + 1]) & 0xFFFF,
                       (c + keys[i + 2]) & 0xFFFF, _idea_mul(d, keys[i + 3]))
        e = _idea_mul(a ^ c, keys[i + 4])
        f = _idea_mul(((b ^ d) + e) & 0xFFFF, keys[i + 5])
        g = (e + f) & 0xFFFF
        a, b, c, d = a ^ f, c ^ f, b ^ g, d ^ g
    return struct.pack(">4H", _idea_mul(a, keys[48]), (c + keys[49]) & 0xFFFF,
                       (b + keys[50]) & 0xFFFF, _idea_mul(d, keys[51]))


def _idea_mask(key: bytes, source: bytes, iv: bytes) -> bytes:
    keys = _idea_keys(key)
    first = _idea_encrypt(_xor(source[:8], iv), keys)
    return first + _idea_encrypt(_xor(source[8:], first), keys)


def _rc6_keys(key: bytes) -> list[int]:
    words = list(struct.unpack("<4I", key))
    keys = [(0xB7E15163 + i * 0x9E3779B9) & _MASK for i in range(44)]
    a = b = i = j = 0
    for _ in range(132):
        a = keys[i] = _rol(keys[i] + a + b, 3)
        b = words[j] = _rol(words[j] + a + b, a + b)
        i, j = (i + 1) % 44, (j + 1) % 4
    return keys


def _rc6_encrypt(block: bytes, keys: list[int]) -> bytes:
    a, b, c, d = struct.unpack("<4I", block)
    b, d = (b + keys[0]) & _MASK, (d + keys[1]) & _MASK
    for i in range(1, 21):
        t, u = _rol(b * (2 * b + 1), 5), _rol(d * (2 * d + 1), 5)
        a = (_rol(a ^ t, u) + keys[2 * i]) & _MASK
        c = (_rol(c ^ u, t) + keys[2 * i + 1]) & _MASK
        a, b, c, d = b, c, d, a
    return struct.pack("<4I", (a + keys[42]) & _MASK, b,
                       (c + keys[43]) & _MASK, d)


def _validate_material(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != 60:
        raise ValueError("Protected GRF key material must contain exactly 60 bytes")


def decode_keys(raw: bytes) -> dict[int, bytes]:
    """Decode and checksum a GRF archive key block (empty means no keys)."""
    if not raw:
        return {}
    if len(raw) < 20 or raw[:4] != b"\x01\x01\0\0":
        raise ValueError("Unsupported or truncated GRF archive key block")
    size, checksum = struct.unpack_from("<II", raw, 12)
    if not size or size % 64 or size // 64 > 65535 or size != len(raw) - 20:
        raise ValueError("GRF archive key-block size mismatch")
    decoded = _cham_cbc(raw[20:], _KEY_DIGEST[:16], _KEY_DIGEST[16:], True)
    if xxhash.xxh32_intdigest(decoded) != checksum:
        raise ValueError("GRF archive key-block checksum mismatch")
    result = {}
    for off in range(0, size, 64):
        key_id, = struct.unpack_from("<I", decoded, off)
        if not 1 <= key_id <= 65535 or key_id in result:
            raise ValueError("Invalid or duplicate GRF archive key record")
        result[key_id] = decoded[off + 4:off + 64]
    return result


def encode_keys(keys: dict[int, bytes], *, timestamp: int = 1) -> bytes:
    """Encode keys with a low-priority positive native revision by default.

    Native archive wrappers skip revision zero and may distribute the newest
    block across mounted archives. An explicit revision therefore affects key
    selection beyond this archive; do not silently substitute current time.
    """
    if (not isinstance(timestamp, int) or isinstance(timestamp, bool)
            or not 1 <= timestamp <= (1 << 63) - 1):
        raise ValueError("GRF archive key timestamp must be an integer in 1..INT64_MAX")
    if not keys:
        return b""
    if len(keys) > 65535:
        raise ValueError("Too many GRF archive keys")
    for key_id, value in keys.items():
        if not isinstance(key_id, int) or not 1 <= key_id <= 65535:
            raise ValueError("GRF archive key ID must be in 1..65535")
        _validate_material(value)
    decoded = b"".join(struct.pack("<I", k) + keys[k] for k in sorted(keys))
    header = b"\x01\x01\0\0" + struct.pack("<QII", timestamp, len(decoded),
                                                  xxhash.xxh32_intdigest(decoded))
    return header + _cham_cbc(decoded, _KEY_DIGEST[:16], _KEY_DIGEST[16:])


def _header_transform(header: bytes, raw_name: bytes, decrypt: bool) -> bytes:
    kind = header[1]
    if kind in (1, 2, 15):
        iv = _AES_IV if kind == 1 else _hash(raw_name if kind == 2 else header[4:8])
        aes = AES.new(_AES_KEY, AES.MODE_CBC, iv)
        body = aes.decrypt(header[8:]) if decrypt else aes.encrypt(header[8:])
    elif kind == 0x71:
        body = _cfb(header[8:], lambda block: _threeway_encrypt(_THREEWAY_KEY, block),
                    _THREEWAY_IV, 12, decrypt)
    else:
        raise ValueError(f"Unsupported protected GRF header type {kind:#x}")
    return header[:8] + body


def _body_transform(tail: bytes, cipher: int, params: bytes, name_hash: bytes,
                    seeded_hash: bytes, output_hash: bytes, compressed_tail: int,
                    decrypt: bool) -> bytes:
    if cipher == 1:
        key = _hash(params[:60], int.from_bytes(seeded_hash[8:], "little"))
        full = len(tail) // 16 * 16
        prefix = min(full, 1024)
        if decrypt:
            tail = _cham_cbc(tail[:prefix], key, output_hash, True) + tail[prefix:]
        output = bytearray()
        previous = output_hash
        for off in range(0, full, 16):
            block = tail[off:off + 16]
            if decrypt:
                rotated = block[12:] + block[:12]
                output.extend(_xor(_xor(rotated, seeded_hash[12:] + seeded_hash[:12]), previous))
                previous = block
            else:
                value = _xor(block, previous)
                previous = _xor(value[4:] + value[:4], seeded_hash)
                output.extend(previous)
        output.extend(b ^ seeded_hash[i] ^ previous[i] for i, b in enumerate(tail[full:]))
        if not decrypt:
            output[:prefix] = _cham_cbc(bytes(output[:prefix]), key, output_hash)
        return bytes(output)
    if cipher in (5, 7):
        if cipher == 5:
            key, iv = params[:16], params[16:32]
            mask = _idea_mask(name_hash, output_hash, params[48:56])
        else:
            key, iv = params[28:44], params[44:60]
            mask = _idea_mask(output_hash, name_hash, params[52:60])
        length = min(compressed_tail, 1024)
        encrypted_length = (length // 16 + 1) * 16
        aes = AES.new(key, AES.MODE_CBC, iv)
        if decrypt:
            if len(tail) != encrypted_length + compressed_tail - length:
                raise ValueError("Protected GRF AES padding size mismatch")
            prefix = aes.decrypt(tail[:encrypted_length])
            pad = encrypted_length - length
            if prefix[length:] != bytes([pad]) * pad:
                raise ValueError("Invalid protected GRF AES PKCS#7 padding")
            suffix = tail[encrypted_length:]
            return prefix[:length] + bytes(b ^ mask[i % 16] for i, b in enumerate(suffix))
        pad = 16 - length % 16
        return (aes.encrypt(tail[:length] + bytes([pad]) * pad)
                + bytes(b ^ mask[i % 16] for i, b in enumerate(tail[length:])))
    mask = (_idea_mask(output_hash, name_hash, params[49:57]) if cipher == 128
            else _idea_mask(name_hash, output_hash, params[49:57]))
    data = bytearray(tail if decrypt else bytes(b ^ mask[i % 16] for i, b in enumerate(tail)))
    if cipher == 128:
        start, size = ((0, len(data) // 16 * 16) if len(data) < 3072 else (2048, 1024))
        aes = AES.new(params[44:60], AES.MODE_CBC, params[28:44])
        part = bytes(data[start:start + size])
        data[start:start + size] = aes.decrypt(part) if decrypt else aes.encrypt(part)
    else:
        keys = _rc6_keys(params[24:40])
        size = min(len(data) // 16 * 16, 1024)
        data[:size] = _cfb(bytes(data[:size]), lambda b: _rc6_encrypt(b, keys),
                            params[40:56], 16, decrypt)
    return bytes(b ^ mask[i % 16] for i, b in enumerate(data)) if decrypt else bytes(data)


def decode_header(payload: bytes, raw_name: bytes) -> bytes:
    """Decrypt and checksum the descriptor without interpreting its body."""
    if not isinstance(raw_name, bytes):
        raise ValueError("GRF filename must be original encoded bytes")
    if len(payload) < 104 or payload[0] != 1:
        raise ValueError("Unsupported or truncated protected GRF header")
    header = _header_transform(payload[:104], raw_name, True)
    checksum, = struct.unpack_from("<I", header, 4)
    if xxhash.xxh32_intdigest(header[8:]) != checksum:
        raise ValueError("Protected GRF header checksum mismatch")
    return header


def decode_entry(payload: bytes, raw_name: bytes, real_size: int,
                 keys: dict[int, bytes]) -> bytes:
    """Decrypt, decompress and verify one exact protected entry payload."""
    header = decode_header(payload, raw_name)
    cipher, compression, flags, padded, compressed, size = struct.unpack_from("<HBBIII", header, 8)
    if size > MAX_OUTPUT_SIZE or size != real_size:
        raise ValueError("Protected GRF output size exceeds limit or differs from file table")
    if padded != len(payload) - 104 or compressed > padded:
        raise ValueError("Protected GRF body size lies outside payload")
    if cipher not in (1, 5, 7, 128, 133):
        raise ValueError(f"Unsupported protected GRF body cipher {cipher}")
    if compression not in (0, 1, 2):
        raise ValueError(f"Unsupported protected GRF compression {compression}")
    if flags & ~1:
        raise ValueError(f"Unsupported protected GRF parameter flags {flags}")
    key_id, = struct.unpack_from("<I", header, 40)
    material = header[44:] if key_id == 0 else keys.get(key_id)
    if material is None:
        raise ValueError(f"Missing GRF archive key {key_id}")
    _validate_material(material)
    output_hash = header[24:40]
    params = bytes(b ^ (output_hash[i % 16] if flags else 0) for i, b in enumerate(material)) + bytes(4)
    body = payload[104:]
    if compressed > 128:
        body = body[:128] + _body_transform(body[128:], cipher, params, _hash(raw_name),
                    _hash(raw_name, size), output_hash, compressed - 128, True)
    body = body[:compressed]
    if compression == 0:
        if len(body) != size:
            raise ValueError("Protected GRF stored output size mismatch")
        output = body
    elif compression == 1:
        try:
            inflater = zlib.decompressobj()
            output = inflater.decompress(body, size + 1)
        except zlib.error as exc:
            raise ValueError(f"Invalid protected GRF zlib stream: {exc}") from exc
        if (len(output) != size or not inflater.eof or inflater.unused_data
                or inflater.unconsumed_tail):
            raise ValueError("Protected GRF zlib stream is truncated or its size differs")
    else:
        try:
            output = lz4.block.decompress(body, uncompressed_size=size)
        except (lz4.block.LZ4BlockError, OverflowError) as exc:
            raise ValueError(f"Invalid protected GRF LZ4 stream: {exc}") from exc
        if len(output) != size:
            raise ValueError("Protected GRF LZ4 output size mismatch")
    if _hash(output) != output_hash:
        raise ValueError("Protected GRF output hash mismatch")
    return output


def encode_entry(data: bytes, raw_name: bytes, *, cipher: int = 128,
                 compression: int = 1, header_type: int = 2, key_id: int = 0,
                 keys: dict[int, bytes] | None = None, material: bytes | None = None,
                 flags: int = 1) -> bytes:
    """Encode content, deriving filename-dependent keys from its destination name.

    For key ID zero, omitted material is generated securely. Other IDs reference
    the supplied archive key map; their material cannot be overridden per entry.
    """
    if not isinstance(data, bytes) or not isinstance(raw_name, bytes):
        raise ValueError("Protected GRF content and filename must be bytes")
    if len(data) > MAX_OUTPUT_SIZE:
        raise ValueError("Protected GRF output size exceeds limit")
    if cipher not in (1, 5, 7, 128, 133) or compression not in (0, 1, 2):
        raise ValueError("Unsupported protected GRF cipher or compression")
    if header_type not in (1, 2, 15, 0x71) or flags not in (0, 1):
        raise ValueError("Unsupported protected GRF header type or parameter flags")
    if not isinstance(key_id, int) or not 0 <= key_id <= 65535:
        raise ValueError("GRF archive key ID must be in 0..65535")
    if key_id:
        if material is not None:
            raise ValueError("Inline material cannot override an archive key")
        material = (keys or {}).get(key_id)
        if material is None:
            raise ValueError(f"Missing GRF archive key {key_id}")
    elif material is None:
        material = secrets.token_bytes(60)
    _validate_material(material)
    packed = (data if compression == 0 else zlib.compress(data) if compression == 1
              else lz4.block.compress(data, store_size=False))
    output_hash = _hash(data)
    params = bytes(b ^ (output_hash[i % 16] if flags else 0) for i, b in enumerate(material)) + bytes(4)
    body = packed
    if len(packed) > 128:
        body = packed[:128] + _body_transform(packed[128:], cipher, params, _hash(raw_name),
                    _hash(raw_name, len(data)), output_hash, len(packed) - 128, False)
    header = bytearray(104)
    header[:2] = bytes([1, header_type])
    struct.pack_into("<HBBIII", header, 8, cipher, compression, flags, len(body), len(packed), len(data))
    header[24:40] = output_hash
    struct.pack_into("<I", header, 40, key_id)
    header[44:] = material
    struct.pack_into("<I", header, 4, xxhash.xxh32_intdigest(header[8:]))
    return _header_transform(bytes(header), raw_name, False) + body
