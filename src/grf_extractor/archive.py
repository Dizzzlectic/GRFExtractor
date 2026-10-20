"""Compatibility interfaces backed by the shared GRF container and codecs."""

from grfkit.archive import (
    Archive,
    HEADER_SIZE,
    MAX_OUTPUT as MAX_OUTPUT_SIZE,
    MAX_PACKED as MAX_PACKED_SIZE,
    decode_ordinary,
    inflate,
)

MAX_FOOTER_SIZE = 20 + 65535 * 64


def decompress_zlib(data, expected_size):
    """Decode an ordinary-sized zlib stream using the shared validation."""
    if not 0 <= expected_size <= MAX_OUTPUT_SIZE or len(data) > MAX_PACKED_SIZE:
        raise ValueError("Zlib input or output exceeds supported size limit")
    return inflate(data, expected_size)


def read_entries(path):
    """Return the legacy tuple API, with absolute payload offsets."""
    with Archive(path) as archive:
        return [(entry.raw_name, entry.compressed_size, entry.aligned_size,
                 entry.real_size, entry.flags, HEADER_SIZE + entry.offset)
                for entry in archive.entries]


def read_archive_keys(path):
    """Return validated archive key material from the shared parser."""
    with Archive(path) as archive:
        return archive.keys
