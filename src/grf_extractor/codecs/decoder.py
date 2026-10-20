"""Compatibility decoder backed by the shared protected-GRF codec."""

import collections
import struct

from grfkit.protected import decode_entry, decode_header


class PortableDecoder:
    """Retain the extraction decoder interface and successful-format counters."""
    def __init__(self, archive_keys=None):
        self.archive_keys = archive_keys or {}
        self.metadata_counts = collections.Counter()

    def decode(self, name, real, payload):
        plain = decode_entry(payload, name, real, self.archive_keys)
        header = decode_header(payload, name)
        cipher, compression = struct.unpack_from("<HB", header, 8)
        self.metadata_counts[(header[1], cipher, compression)] += 1
        return plain

    def close(self):
        pass
