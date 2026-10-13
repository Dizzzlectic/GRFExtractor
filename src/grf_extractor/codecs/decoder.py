"""Validated portable decoding of protected GRF entries."""

import collections
import struct
import zlib

from ..archive import MAX_OUTPUT_SIZE, decompress_zlib


class PortableDecoder:
    """Checked decoding for the five body formats proven against native callbacks."""
    def __init__(self, archive_keys=None):
        self.archive_keys = archive_keys or {}
        self.metadata_counts = collections.Counter()

    def decode(self, name, real, payload):
        from .bodies import decrypt_tail, prepare_parameters
        from .headers import decode_header, xxh128_native
        import xxhash

        header = decode_header(payload, name)
        cipher_id, compression = struct.unpack_from("<HB", header, 8)
        padded, compressed, size = struct.unpack_from("<III", header, 12)
        if size != real or size > MAX_OUTPUT_SIZE:
            raise ValueError("Protected output size exceeds limit or differs from file table")
        if padded > len(payload) - 104 or compressed > padded:
            raise ValueError("Protected body size lies outside payload")
        if cipher_id not in (1, 5, 7, 128, 133):
            raise ValueError(f"Unsupported portable body cipher {cipher_id}")
        if compression not in (0, 1, 2):
            raise ValueError(f"Unsupported protected compression {compression}")
        parameters = prepare_parameters(header, self.archive_keys)
        body = payload[104:104 + padded]
        if compressed > 128:
            seeded = xxhash.xxh3_128_intdigest(name, seed=size).to_bytes(16, "little")
            tail = decrypt_tail(cipher_id, parameters, xxh128_native(name), header[24:40], body[128:],
                                seeded_filename_hash=seeded, compressed_length=compressed - 128)
            body = body[:128] + tail
        body = body[:compressed]
        if compression == 0:
            plain = body
        elif compression == 1:
            try:
                plain = decompress_zlib(body, size)
            except zlib.error as error:
                raise ValueError(f"Invalid protected zlib stream: {error}") from error
        else:
            import lz4.block
            plain = lz4.block.decompress(body, uncompressed_size=size)
        if len(plain) != size:
            raise ValueError("Protected decompressed size mismatch")
        if xxh128_native(plain) != header[24:40]:
            raise ValueError("Protected decompressed content checksum mismatch")
        self.metadata_counts[(header[1], cipher_id, compression)] += 1
        return plain

    def close(self):
        pass
