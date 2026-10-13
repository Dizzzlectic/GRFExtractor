"""Explicit reference-based repairs; none represent lossless extraction."""

import hashlib
import zlib


WAV_NAME = b"data\\wav\\worm_tail_damage.wav"
WAV_INPUT_SHA256 = "df4f72d0eef4765118980484b2d2229cef815d432d4955dfdb0746b96d4d317c"
WAV_OUTPUT_SHA256 = "6175b2ef4ce814201f607d173a2d322e93eb011153c780e3660a6e0ab9afda67"


def repair_known_wav(name, packed, aligned, real, flags, payload, original_error):
    """Return the documented reference WAV only for its exact truncated input."""
    if (name != WAV_NAME or flags != 1 or (packed, aligned, real) != (1410, 1410, 1410)
            or len(payload) != aligned
            or hashlib.sha256(payload).hexdigest() != WAV_INPUT_SHA256):
        return None

    # One final stored DEFLATE block declares 1410 bytes after its seven-byte
    # zlib/block header. Only 1403 bytes survive; there is no Adler-32 trailer.
    if payload[:7] != bytes.fromhex("789c0182057dfa"):
        raise ValueError("Known WAV repair header mismatch")
    decoder = zlib.decompressobj()
    partial = decoder.decompress(payload)
    if (len(partial) != 1403 or decoder.eof
            or decoder.unused_data or decoder.unconsumed_tail):
        raise ValueError("Known WAV repair decoding mismatch")

    plain = partial + bytes(7)
    if hashlib.sha256(plain).hexdigest() != WAV_OUTPUT_SHA256:
        raise ValueError("Known WAV repair output hash mismatch")
    return plain, {
        "name_hex": name.hex(),
        "input_sha256": WAV_INPUT_SHA256,
        "output_sha256": WAV_OUTPUT_SHA256,
        "method": "Append seven zero metadata bytes to match the dated reference",
        "missing_metadata_bytes": 7,
        "missing_checksum_bytes": 4,
        "original_error": str(original_error).splitlines()[0],
        "reference": "kRO-2026-02-19/data.grf: data\\wav\\worm_tail_damage.wav",
        "metadata_ambiguous": True,
        "lossless": False,
        "note": "The reference matches all surviving bytes; the missing original metadata and checksum cannot be recovered.",
    }
