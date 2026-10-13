"""Legacy GRF entry decryption (flags 3 and 5), before zlib decompression.

GPL-3.0-or-later. Tables and transform follow roBrowserLegacy-RemoteClient-Rust
src/des.rs and scripts/grf_des.py, revision 66ba94e2b84c4092e4b9cc9d0dcc805313438f53.
The precomputed permutations preserve that implementation's single DES round.
"""

INITIAL_PERMUTATION_TABLE = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]

FINAL_PERMUTATION_TABLE = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]

TRANSPOSITION_TABLE = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]

SUBSTITUTION_BOX_TABLE = [
    [
        0xEF, 0x03, 0x41, 0xFD, 0xD8, 0x74, 0x1E, 0x47, 0x26, 0xEF, 0xFB, 0x22, 0xB3, 0xD8, 0x84, 0x1E,
        0x39, 0xAC, 0xA7, 0x60, 0x62, 0xC1, 0xCD, 0xBA, 0x5C, 0x96, 0x90, 0x59, 0x05, 0x3B, 0x7A, 0x85,
        0x40, 0xFD, 0x1E, 0xC8, 0xE7, 0x8A, 0x8B, 0x21, 0xDA, 0x43, 0x64, 0x9F, 0x2D, 0x14, 0xB1, 0x72,
        0xF5, 0x5B, 0xC8, 0xB6, 0x9C, 0x37, 0x76, 0xEC, 0x39, 0xA0, 0xA3, 0x05, 0x52, 0x6E, 0x0F, 0xD9,
    ],
    [
        0xA7, 0xDD, 0x0D, 0x78, 0x9E, 0x0B, 0xE3, 0x95, 0x60, 0x36, 0x36, 0x4F, 0xF9, 0x60, 0x5A, 0xA3,
        0x11, 0x24, 0xD2, 0x87, 0xC8, 0x52, 0x75, 0xEC, 0xBB, 0xC1, 0x4C, 0xBA, 0x24, 0xFE, 0x8F, 0x19,
        0xDA, 0x13, 0x66, 0xAF, 0x49, 0xD0, 0x90, 0x06, 0x8C, 0x6A, 0xFB, 0x91, 0x37, 0x8D, 0x0D, 0x78,
        0xBF, 0x49, 0x11, 0xF4, 0x23, 0xE5, 0xCE, 0x3B, 0x55, 0xBC, 0xA2, 0x57, 0xE8, 0x22, 0x74, 0xCE,
    ],
    [
        0x2C, 0xEA, 0xC1, 0xBF, 0x4A, 0x24, 0x1F, 0xC2, 0x79, 0x47, 0xA2, 0x7C, 0xB6, 0xD9, 0x68, 0x15,
        0x80, 0x56, 0x5D, 0x01, 0x33, 0xFD, 0xF4, 0xAE, 0xDE, 0x30, 0x07, 0x9B, 0xE5, 0x83, 0x9B, 0x68,
        0x49, 0xB4, 0x2E, 0x83, 0x1F, 0xC2, 0xB5, 0x7C, 0xA2, 0x19, 0xD8, 0xE5, 0x7C, 0x2F, 0x83, 0xDA,
        0xF7, 0x6B, 0x90, 0xFE, 0xC4, 0x01, 0x5A, 0x97, 0x61, 0xA6, 0x3D, 0x40, 0x0B, 0x58, 0xE6, 0x3D,
    ],
    [
        0x4D, 0xD1, 0xB2, 0x0F, 0x28, 0xBD, 0xE4, 0x78, 0xF6, 0x4A, 0x0F, 0x93, 0x8B, 0x17, 0xD1, 0xA4,
        0x3A, 0xEC, 0xC9, 0x35, 0x93, 0x56, 0x7E, 0xCB, 0x55, 0x20, 0xA0, 0xFE, 0x6C, 0x89, 0x17, 0x62,
        0x17, 0x62, 0x4B, 0xB1, 0xB4, 0xDE, 0xD1, 0x87, 0xC9, 0x14, 0x3C, 0x4A, 0x7E, 0xA8, 0xE2, 0x7D,
        0xA0, 0x9F, 0xF6, 0x5C, 0x6A, 0x09, 0x8D, 0xF0, 0x0F, 0xE3, 0x53, 0x25, 0x95, 0x36, 0x28, 0xCB,
    ],
]

SHUFFLE_PAIRS = [
    (0x00, 0x2B), (0x6C, 0x80), (0x01, 0x68), (0x48, 0x77),
    (0x60, 0xFF), (0xB9, 0xC0), (0xFE, 0xEB),
]



def _permutation_tables(positions):
    tables = []
    for byte in range(8):
        table = []
        for value in range(256):
            result = 0
            for dest, source in enumerate(positions):
                if (source - 1) // 8 == byte and value & (128 >> ((source - 1) % 8)):
                    result |= 1 << (63 - dest)
            table.append(result)
        tables.append(table)
    return tables


_IP = _permutation_tables(INITIAL_PERMUTATION_TABLE)
_FP = _permutation_tables(FINAL_PERMUTATION_TABLE)


def _round_tables():
    tables = []
    for group in range(4):
        table = []
        for value in range(1024):
            upper, lower = value >> 4, value & 63
            substituted = (SUBSTITUTION_BOX_TABLE[group][upper] & 240) | (SUBSTITUTION_BOX_TABLE[group][lower] & 15)
            before = substituted << (24 - group * 8)
            after = 0
            for dest, source in enumerate(TRANSPOSITION_TABLE):
                if before & (1 << (32 - source)):
                    after |= 1 << (31 - dest)
            table.append(after)
        tables.append(table)
    return tables


_F = _round_tables()
_SHUFFLE = bytes(range(256))
_shuffle = bytearray(_SHUFFLE)
for _a, _b in SHUFFLE_PAIRS:
    _shuffle[_a], _shuffle[_b] = _b, _a
_SHUFFLE = bytes(_shuffle)


def _block(data, offset):
    value = 0
    for i in range(8):
        value ^= _IP[i][data[offset + i]]
    right = value & 0xffffffff
    round_result = (_F[0][((right >> 23) & 511) | ((right & 1) << 9)]
                    ^ _F[1][(right >> 15) & 1023]
                    ^ _F[2][(right >> 7) & 1023]
                    ^ _F[3][((right & 511) << 1) | (right >> 31)])
    value ^= round_result << 32
    result = 0
    for i in range(8):
        result ^= _FP[i][(value >> (56 - 8 * i)) & 255]
    data[offset:offset + 8] = result.to_bytes(8, 'big')


def decode_legacy(payload: bytes, flags: int, packed_size: int) -> bytes:
    """Return decrypted compressed bytes, retaining the archive's alignment padding."""
    if flags not in (3, 5):
        raise ValueError('Legacy GRF decryption requires flags 3 or 5')
    if not 0 <= packed_size <= len(payload):
        raise ValueError('Packed size exceeds the provided payload')
    data = bytearray(payload)
    blocks = len(data) // 8
    for block in range(min(20, blocks)):
        _block(data, block * 8)
    if flags == 3:
        digits = len(str(packed_size))
        cycle = 1 if digits < 3 else digits + (1 if digits < 5 else 9 if digits < 7 else 15)
        skipped = -1
        for block in range(20, blocks):
            at = block * 8
            if block % cycle == 0:
                _block(data, at)
                continue
            skipped += 1
            if skipped and skipped % 7 == 0:
                original = data[at:at + 8]
                data[at:at + 8] = bytes((original[3], original[4], original[6], original[0],
                                       original[1], original[2], original[5], _SHUFFLE[original[7]]))
    return bytes(data)
