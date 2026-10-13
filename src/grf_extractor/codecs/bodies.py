"""Portable body ciphers 1, 5, 7, 128 and 133 for the supported GRF format.

Inputs are the prepared 64-byte parameters and native little-endian hashes.
The tail begins after the first 128 clear compressed bytes. Ciphers 5 and 7
remove AES padding; the others preserve tail length. The caller must use the
decoded header's compressed size and verify its final output hash. Cipher 1
needs the filename hash seeded by output size, while 5/7 need plaintext tail
length. See docs/format.md.
"""

from Crypto.Cipher import AES

import struct

import xxhash

from .footer import cham_keys, cham_decrypt

MASK32 = 0xffffffff


def _multiply(a, b):
    return (((a or 65536) * (b or 65536)) % 65537) & 0xffff


def _idea_keys(key):
    value = int.from_bytes(key, 'big')
    words = []
    while len(words) < 52:
        words.extend((value >> (112 - 16 * i)) & 0xffff for i in range(8))
        value = ((value << 25) | (value >> 103)) & ((1 << 128) - 1)
    return words[:52]


def idea_encrypt(block, keys):
    a, b, c, d = struct.unpack('>4H', block)
    for off in range(0, 48, 6):
        k = keys[off:off + 6]
        a, b, c, d = _multiply(a, k[0]), (b + k[1]) & 0xffff, (c + k[2]) & 0xffff, _multiply(d, k[3])
        e = _multiply(a ^ c, k[4])
        f = _multiply(((b ^ d) + e) & 0xffff, k[5])
        g = (e + f) & 0xffff
        a, b, c, d = a ^ f, c ^ f, b ^ g, d ^ g
    return struct.pack('>4H', _multiply(a, keys[48]), (c + keys[49]) & 0xffff,
                       (b + keys[50]) & 0xffff, _multiply(d, keys[51]))


def _rol(value, count):
    count &= 31
    return ((value << count) | (value >> ((32 - count) & 31))) & MASK32


def _rc6_keys(key):
    words = list(struct.unpack('<4I', key))
    keys = [(0xb7e15163 + i * 0x9e3779b9) & MASK32 for i in range(44)]
    a = b = i = j = 0
    for _ in range(132):
        a = keys[i] = _rol((keys[i] + a + b) & MASK32, 3)
        b = words[j] = _rol((words[j] + a + b) & MASK32, a + b)
        i, j = (i + 1) % 44, (j + 1) % 4
    return keys


def rc6_encrypt(block, keys):
    a, b, c, d = struct.unpack('<4I', block)
    b = (b + keys[0]) & MASK32
    d = (d + keys[1]) & MASK32
    for i in range(1, 21):
        t = _rol((b * (2 * b + 1)) & MASK32, 5)
        u = _rol((d * (2 * d + 1)) & MASK32, 5)
        a = (_rol(a ^ t, u) + keys[2 * i]) & MASK32
        c = (_rol(c ^ u, t) + keys[2 * i + 1]) & MASK32
        a, b, c, d = b, c, d, a
    a = (a + keys[42]) & MASK32
    c = (c + keys[43]) & MASK32
    return struct.pack('<4I', a, b, c, d)


def _decrypt133(parameters, filename_hash, output_hash, tail):
    if len(parameters) != 64 or len(filename_hash) != 16 or len(output_hash) != 16:
        raise ValueError('Expected 64-byte parameters and two 16-byte hashes')
    keys = _idea_keys(filename_hash)
    first = idea_encrypt(bytes(a ^ b for a, b in zip(output_hash[:8], parameters[49:57])), keys)
    second = idea_encrypt(bytes(a ^ b for a, b in zip(output_hash[8:], first)), keys)
    mask = first + second
    output = bytearray(tail)
    keys = _rc6_keys(parameters[24:40])
    previous = parameters[40:56]
    for offset in range(0, min(1024, len(tail) // 16 * 16), 16):
        block = tail[offset:offset + 16]
        stream = rc6_encrypt(previous, keys)
        output[offset:offset + 16] = bytes(a ^ b for a, b in zip(block, stream))
        previous = block
    for i in range(len(output)):
        output[i] ^= mask[i % 16]
    return bytes(output)


def _decrypt1(parameters, output_hash, tail, seeded_filename_hash):
    if seeded_filename_hash is None or len(seeded_filename_hash) != 16:
        raise ValueError("Body cipher 1 requires a filename hash seeded by output size")
    mask = seeded_filename_hash
    seed = int.from_bytes(mask[8:], "little")
    key = xxhash.xxh3_128_intdigest(parameters[:60], seed=seed).to_bytes(16, "little")
    keys = cham_keys(key)
    output = bytearray(tail)
    full_length = len(tail) // 16 * 16
    previous = output_hash
    for offset in range(0, min(1024, full_length), 16):
        block = tail[offset:offset + 16]
        output[offset:offset + 16] = bytes(a ^ b for a, b in zip(cham_decrypt(block, keys), previous))
        previous = block
    previous = output_hash
    for offset in range(0, full_length, 16):
        block = bytes(output[offset:offset + 16])
        mixed = bytes(a ^ b for a, b in zip(block, mask))
        rotated = mixed[12:] + mixed[:12]
        output[offset:offset + 16] = bytes(a ^ b for a, b in zip(rotated, previous))
        previous = block
    for i in range(len(tail) - full_length):
        output[full_length + i] ^= mask[i] ^ previous[i]
    return bytes(output)


def _decrypt57(cipher_id, parameters, filename_hash, output_hash, tail, compressed_length):
    if compressed_length is None or compressed_length < 0:
        raise ValueError("Body ciphers 5/7 require the compressed plaintext tail length")
    length = min(compressed_length, 1024)
    encrypted_length = (length // 16 + 1) * 16
    if len(tail) != encrypted_length + compressed_length - length:
        raise ValueError("Body cipher 5/7 AES padding size mismatch")
    if cipher_id == 5:
        key, source, iv = filename_hash, output_hash, parameters[48:56]
        aes_key, aes_iv = parameters[:16], parameters[16:32]
    else:
        key, source, iv = output_hash, filename_hash, parameters[52:60]
        aes_key, aes_iv = parameters[28:44], parameters[44:60]
    decoded = AES.new(aes_key, AES.MODE_CBC, aes_iv).decrypt(tail[:encrypted_length])
    padding = decoded[-1]
    if not 1 <= padding <= 16 or encrypted_length - padding != length or decoded[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid body cipher 5/7 AES PKCS#7 padding")
    keys = _idea_keys(key)
    first = idea_encrypt(bytes(a ^ b for a, b in zip(source[:8], iv)), keys)
    second = idea_encrypt(bytes(a ^ b for a, b in zip(source[8:], first)), keys)
    mask = first + second
    suffix = bytes(value ^ mask[i % 16] for i, value in enumerate(tail[encrypted_length:]))
    return decoded[:length] + suffix


def prepare_parameters(header, archive_keys):
    if len(header) != 104:
        raise ValueError("Expected a decoded 104-byte header")
    key_id = struct.unpack_from("<I", header, 40)[0]
    flags = header[11]
    if flags & ~1:
        raise ValueError(f"Unsupported parameter flags {flags}")
    if key_id:
        if key_id not in archive_keys:
            raise ValueError(f"Missing archive key {key_id}")
        material = archive_keys[key_id]
    else:
        material = header[44:104]
    if len(material) != 60:
        raise ValueError("Expected 60-byte parameter material")
    if flags & 1:
        material = bytes(value ^ header[24 + i % 16] for i, value in enumerate(material))
    return material + bytes(4)


def decrypt_tail(cipher_id, parameters, filename_hash, output_hash, tail, *,
                 seeded_filename_hash=None, compressed_length=None):
    if len(parameters) != 64 or len(filename_hash) != 16 or len(output_hash) != 16:
        raise ValueError("Expected 64-byte parameters and two 16-byte hashes")
    if cipher_id == 1:
        return _decrypt1(parameters, output_hash, tail, seeded_filename_hash)
    if cipher_id in (5, 7):
        return _decrypt57(cipher_id, parameters, filename_hash, output_hash, tail, compressed_length)
    if cipher_id == 133:
        return _decrypt133(parameters, filename_hash, output_hash, tail)
    if cipher_id != 128:
        raise ValueError(f"Unsupported portable body cipher {cipher_id}")
    keys = _idea_keys(output_hash)
    first = idea_encrypt(bytes(a ^ b for a, b in zip(filename_hash[:8], parameters[49:57])), keys)
    second = idea_encrypt(bytes(a ^ b for a, b in zip(filename_hash[8:], first)), keys)
    mask = first + second
    output = bytearray(tail)
    if len(tail) < 3072:
        start, length = 0, len(tail) // 16 * 16
    else:
        start, length = 2048, 1024
    if length:
        output[start:start + length] = AES.new(parameters[44:60], AES.MODE_CBC,
                                             parameters[28:44]).decrypt(tail[start:start + length])
    return bytes(value ^ mask[i % 16] for i, value in enumerate(output))
