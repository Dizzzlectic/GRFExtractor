"""GRF v2/v3 tables, archive keys and ordinary entry decoding."""

import struct
import zlib

MAX_OUTPUT_SIZE = 256 * 1024 * 1024
MAX_PACKED_SIZE = 258 * 1024 * 1024
MAX_FOOTER_SIZE = 20 + 65535 * 64


def decompress_zlib(data, expected_size):
    """Bound expansion and require one complete stream of exactly the declared size."""
    if not 0 <= expected_size <= MAX_OUTPUT_SIZE or len(data) > MAX_PACKED_SIZE:
        raise ValueError("Zlib input or output exceeds supported size limit")
    inflater = zlib.decompressobj()
    plain = inflater.decompress(data, expected_size + 1)
    if not inflater.eof:
        raise zlib.error("Error -5 while decompressing data: incomplete, truncated or oversized stream")
    if inflater.unused_data or inflater.unconsumed_tail or len(plain) != expected_size:
        raise zlib.error("Zlib stream has trailing data or differs from declared output size")
    return plain


def read_entries(path):
    archive_size = path.stat().st_size
    with path.open("rb") as source:
        header = source.read(46)
        if len(header) != 46:
            raise ValueError("Truncated GRF header")
        if header[:15].split(b"\0", 1)[0] not in (b"Master of Magic", b"Event Horizon"):
            raise ValueError("Invalid GRF signature")
        low, high, count, version = struct.unpack_from("<IIII", header, 30)
        if version == 0x300:
            table_offset = (high << 32) + low + 46
            prefix_size = 12
            record = struct.Struct("<IIIBQ")
        elif version == 0x200:
            count -= high + 7  # v2 stores a reserved-field bias, not an offset high word.
            if count < 0:
                raise ValueError("Invalid GRF entry count")
            table_offset = low + 46
            prefix_size = 8
            record = struct.Struct("<IIIBI")
        else:
            raise ValueError(f"Unsupported GRF version {version:#x}")
        if table_offset + prefix_size > archive_size:
            raise ValueError("GRF table header lies outside archive")
        source.seek(table_offset)
        prefix = source.read(prefix_size)
        if len(prefix) != prefix_size:
            raise ValueError("Truncated GRF table header")
        packed_size, real_size = struct.unpack_from("<II", prefix, prefix_size - 8)
        if packed_size > MAX_PACKED_SIZE or real_size > MAX_OUTPUT_SIZE:
            raise ValueError("GRF table exceeds supported size limit")
        if table_offset + prefix_size + packed_size > archive_size:
            raise ValueError("GRF table lies outside archive")
        packed_table = source.read(packed_size)
        if len(packed_table) != packed_size:
            raise ValueError("Truncated GRF table")
        table = decompress_zlib(packed_table, real_size)
    entries = []
    position = 0
    while position < len(table):
        end = table.index(0, position)
        if end + 1 + record.size > len(table):
            raise ValueError("Truncated GRF table record")
        name = table[position:end]
        packed, aligned, real, flags, offset = record.unpack_from(table, end + 1)
        if packed > aligned or aligned > MAX_PACKED_SIZE or real > MAX_OUTPUT_SIZE:
            raise ValueError("GRF entry sizes are inconsistent or exceed supported limits")
        if offset + 46 + aligned > archive_size:
            raise ValueError("Entry lies outside archive")
        entries.append((name, packed, aligned, real, flags, offset + 46))
        position = end + 1 + record.size
    if len(entries) != count:
        raise ValueError(f"GRF entry count mismatch: expected {count}, found {len(entries)}")
    return entries


def read_archive_keys(path):
    archive_size = path.stat().st_size
    with path.open("rb") as source:
        header = source.read(46)
        if len(header) != 46:
            raise ValueError("Truncated GRF header")
        low, high, _count, version = struct.unpack_from("<IIII", header, 30)
        if version == 0x200:
            return {}
        if version != 0x300:
            raise ValueError(f"Unsupported GRF version {version:#x}")
        table_offset = (high << 32) + low + 46
        if table_offset + 12 > archive_size:
            raise ValueError("GRF table header lies outside archive")
        source.seek(table_offset)
        sizes = source.read(12)
        if len(sizes) != 12:
            raise ValueError("Truncated GRF table header")
        footer_size, packed_size, real_size = struct.unpack("<III", sizes)
        if footer_size > MAX_FOOTER_SIZE or packed_size > MAX_PACKED_SIZE or real_size > MAX_OUTPUT_SIZE:
            raise ValueError("GRF table or key block exceeds supported size limit")
        footer_offset = table_offset + 12 + packed_size
        if footer_offset + footer_size > archive_size:
            raise ValueError("GRF key block lies outside archive")
        if not footer_size:
            return {}
        source.seek(footer_offset)
        raw = source.read(footer_size)
        if len(raw) != footer_size:
            raise ValueError("Truncated GRF key block")
        from .codecs.footer import decode_footer
        return decode_footer(raw)


def decode_ordinary(name, packed, aligned, real, flags, payload, *, allow_repair=False):
    """Decode older entries with bounded output, keeping the explicit WAV repair."""
    if not 0 <= packed <= aligned <= MAX_PACKED_SIZE or not 0 <= real <= MAX_OUTPUT_SIZE:
        raise ValueError("GRF entry sizes are inconsistent or exceed supported limits")
    if len(payload) != aligned:
        raise ValueError("Truncated entry")
    repair = None
    if not packed and not real:
        plain = b""
    elif flags == 1:
        try:
            plain = decompress_zlib(payload[:packed], real)
        except zlib.error as error:
            if not allow_repair:
                raise
            from .repairs import repair_known_wav
            repaired = repair_known_wav(name, packed, aligned, real, flags, payload, error)
            if repaired is None:
                raise
            plain, repair = repaired
    elif flags in (3, 5):
        from .codecs.legacy import decode_legacy
        plain = decompress_zlib(decode_legacy(payload, flags, packed)[:packed], real)
    elif flags == 0 and packed == real:
        plain = payload[:real]
    else:
        raise ValueError(f"Unsupported flags {flags:#x}")
    if len(plain) != real:
        raise ValueError("Extracted size mismatch")
    return plain, repair
