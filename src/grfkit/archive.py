"""Bounded GRF v2/v3 container reader and atomic writer. SPDX-License-Identifier: GPL-3.0-or-later"""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import zlib

HEADER_SIZE = 46
MAX_OUTPUT = 256 * 1024 * 1024
MAX_PACKED = MAX_OUTPUT + 2 * 1024 * 1024
MAX_TABLE = 512 * 1024 * 1024
MAX_ENTRIES = 500_000
WAV_NAME = b"data\\wav\\worm_tail_damage.wav"
WAV_PAYLOAD_SHA256 = "df4f72d0eef4765118980484b2d2229cef815d432d4955dfdb0746b96d4d317c"
WAV_OUTPUT_SHA256 = "6175b2ef4ce814201f607d173a2d322e93eb011153c780e3660a6e0ab9afda67"


def inflate(data, expected):
    if not 0 <= expected <= MAX_TABLE or len(data) > MAX_TABLE + 1024 * 1024:
        raise ValueError("zlib input or output exceeds supported size limit")
    stream = zlib.decompressobj()
    try:
        result = stream.decompress(data, expected + 1)
    except zlib.error as error:
        raise ValueError(f"invalid zlib stream: {error}") from error
    if len(result) != expected or not stream.eof or stream.unused_data or stream.unconsumed_tail:
        raise ValueError(f"incomplete zlib stream or output size mismatch (expected {expected}, got {len(result)})")
    return result


def _zlib_header(data):
    return len(data) >= 2 and data[0] & 15 == 8 and data[0] >> 4 <= 7 and int.from_bytes(data[:2], "big") % 31 == 0


def repair_known_wav(name, packed, aligned, real, flags, payload, original_error):
    """Repair only the exact known truncated WAV and describe the lost metadata."""
    if (name != WAV_NAME or flags != 1 or (packed, aligned, real) != (1410, 1410, 1410)
            or len(payload) != aligned or hashlib.sha256(payload).hexdigest() != WAV_PAYLOAD_SHA256):
        return None
    if payload[:7] != bytes.fromhex("789c0182057dfa"):
        raise ValueError("known WAV repair header mismatch")
    decoder = zlib.decompressobj()
    partial = decoder.decompress(payload, 1411)
    if (len(partial) != 1403 or decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or partial[:4] != b"RIFF" or partial[8:12] != b"WAVE"
            or struct.unpack_from("<I", partial, 4)[0] + 8 != 1410
            or partial[36:40] != b"data" or struct.unpack_from("<I", partial, 40)[0] + 44 != 1322
            or partial[1322:1326] != b"LIST"):
        raise ValueError("known WAV structure differs; refusing repair")
    output = partial + bytes(7)
    if hashlib.sha256(output).hexdigest() != WAV_OUTPUT_SHA256:
        raise ValueError("known WAV repair output hash mismatch")
    return output, {
        "name_hex": name.hex(),
        "input_sha256": WAV_PAYLOAD_SHA256,
        "output_sha256": WAV_OUTPUT_SHA256,
        "method": "Append seven zero bytes to replace missing WAV metadata",
        "missing_metadata_bytes": 7,
        "missing_checksum_bytes": 4,
        "original_error": str(original_error).splitlines()[0],
        "reference": "https://github.com/Dizzzlectic/GRFExtractor/blob/main/docs/extraction.md#repair-the-known-truncated-wav",
        "metadata_ambiguous": True,
        "lossless": False,
        "note": "All surviving audio is preserved; zero-filling does not recover the missing original metadata or compressed-stream checksum.",
    }


def decode_ordinary(name, packed, aligned, real, flags, payload, *, allow_repair=False):
    """Decode one ordinary entry and return its bytes and optional repair description."""
    if not 0 <= packed <= aligned <= MAX_PACKED or not 0 <= real <= MAX_OUTPUT:
        raise ValueError("invalid entry compressed/aligned/output size")
    if len(payload) != aligned:
        raise ValueError("truncated entry payload")
    if flags not in (0, 1, 3, 5):
        raise ValueError(f"unsupported entry flags {flags:#x}")
    if flags & 6:
        from .legacy import decode_full, encode_header
        payload = (decode_full(payload, len(payload), packed) if flags & 2
                   else encode_header(payload, len(payload)))
    data = payload[:packed]
    if not data and real == 0:
        return b"", None
    if real == packed and (flags == 0 or not _zlib_header(data)):
        return data, None
    try:
        return inflate(data, real), None
    except ValueError as error:
        repaired = repair_known_wav(name, packed, aligned, real, flags, payload, error) if allow_repair else None
        if repaired is None:
            raise
        return repaired


@dataclass(frozen=True)
class Entry:
    index: int
    raw_name: bytes
    compressed_size: int
    aligned_size: int
    real_size: int
    flags: int
    offset: int

    @property
    def protected(self):
        return bool(self.flags & 0x80)

    @property
    def is_file(self):
        return bool(self.flags & 0x81) or (self.flags == 0 and self.real_size > 0 and self.real_size == self.compressed_size)

    @property
    def name(self):
        return self.raw_name.decode("cp949", errors="surrogateescape").replace("\\", "/")


class Archive:
    def __init__(self, path):
        self.path = Path(path)
        self.handle = self.path.open("rb")
        try:
            self.size = os.fstat(self.handle.fileno()).st_size
            header = self._read(0, HEADER_SIZE)
            if header[:15].split(b"\0")[0] not in (b"Master of Magic", b"Event Horizon"):
                raise ValueError("unrecognized GRF signature")
            self.version = struct.unpack_from("<I", header, 42)[0]
            if self.version == 0x300 and struct.unpack_from("<I", header, 34)[0] >> 8:
                self.version = 0x200  # GRFEditor-compatible mislabeled container
            if self.version == 0x300:
                offset, count = struct.unpack_from("<QI", header, 30)
            elif self.version == 0x200:
                offset, reserved, count = struct.unpack_from("<III", header, 30)
                count -= reserved + 7
            else:
                raise ValueError(f"unsupported GRF version {self.version:#x}; expected 0x200/0x300")
            if not 0 <= count <= MAX_ENTRIES:
                raise ValueError("invalid or excessive GRF entry count")
            self.table_offset = offset + HEADER_SIZE
            self.raw_keys = b""
            self.keys = {}
            self.repaired_indices = set()
            cursor = self.table_offset
            key_size = 0
            if self.version == 0x300:
                key_size, = struct.unpack("<I", self._read(cursor, 4))
                if key_size > 20 + 65535 * 64:
                    raise ValueError("excessive archive key block size")
                cursor += 4
            compressed_size, real_size = struct.unpack("<II", self._read(cursor, 8))
            if real_size > MAX_TABLE or compressed_size > MAX_TABLE + 1024 * 1024:
                raise ValueError("excessive GRF file table size")
            table = inflate(self._read(cursor + 8, compressed_size), real_size)
            if key_size:
                from .protected import decode_keys
                self.raw_keys = self._read(cursor + 8 + compressed_size, key_size)
                self.keys = decode_keys(self.raw_keys)
            entry_struct = struct.Struct("<IIIBQ" if self.version == 0x300 else "<IIIBI")
            self.entries = []
            cursor = 0
            for index in range(count):
                end = table.find(b"\0", cursor)
                if end < cursor or end - cursor > 4096 or end + 1 + entry_struct.size > len(table):
                    raise ValueError(f"invalid file table entry {index} (entry count mismatch)")
                csize, aligned, output, flags, relative = entry_struct.unpack_from(table, end + 1)
                entry = Entry(index, table[cursor:end], csize, aligned, output, flags, relative)
                if flags not in (0, 1, 2, 3, 5, 0x80) or (not entry.is_file and (csize or aligned or output)):
                    raise ValueError(f"unsupported flags or nonempty directory at entry {index}")
                if csize > aligned or aligned > MAX_PACKED or output > MAX_OUTPUT:
                    raise ValueError(f"invalid entry compressed/aligned/output size at entry {index}")
                if HEADER_SIZE + relative + aligned > self.size:
                    raise ValueError(f"entry {index} lies outside archive")
                self.entries.append(entry)
                cursor = end + 1 + entry_struct.size
            if cursor != len(table):
                raise ValueError("entry count mismatch: unexpected bytes after declared file table entries")
        except BaseException:
            self.handle.close()
            raise

    def _read(self, offset, length):
        if offset < 0 or length < 0 or offset + length > self.size:
            raise ValueError(f"read outside archive at {offset} length {length}")
        self.handle.seek(offset)
        data = self.handle.read(length)
        if len(data) != length:
            raise ValueError("archive changed or was truncated during read")
        return data

    def payload(self, entry):
        if entry.compressed_size > entry.aligned_size or entry.aligned_size > MAX_PACKED:
            raise ValueError("invalid entry compressed/aligned size")
        return self._read(HEADER_SIZE + entry.offset, entry.aligned_size)

    def read(self, entry, *, repair_known_wav=False):
        if not entry.is_file:
            raise ValueError("entry is a directory")
        if entry.real_size > MAX_OUTPUT:
            raise ValueError("entry output exceeds 256 MiB limit")
        if entry.flags not in (0, 1, 3, 5, 0x80):
            raise ValueError(f"unsupported entry flags {entry.flags:#x}")
        data = self.payload(entry)
        if entry.protected:
            from .protected import decode_entry
            return decode_entry(data[:entry.compressed_size], entry.raw_name, entry.real_size, self.keys)
        output, repair = decode_ordinary(entry.raw_name, entry.compressed_size, entry.aligned_size,
                                        entry.real_size, entry.flags, data, allow_repair=repair_known_wav)
        if repair is not None:
            self.repaired_indices.add(entry.index)
        return output

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.handle.close()


class Writer:
    def __init__(self, path, *, version=0x300, keys=None, raw_keys=None):
        if version not in (0x200, 0x300):
            raise ValueError("writer version must be 0x200 or 0x300")
        self.path = Path(path)
        if self.path.exists():
            raise FileExistsError(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.version = version
        self.keys = dict(keys or {})
        if raw_keys is not None:
            from .protected import decode_keys
            decoded_keys = decode_keys(raw_keys)
            if keys is not None and decoded_keys != self.keys:
                raise ValueError("archive key material differs from serialized key block")
            self.keys = decoded_keys
        elif self.keys:
            from .protected import encode_keys
            raw_keys = encode_keys(self.keys)
        self.raw_keys = raw_keys or b""
        if version == 0x200 and self.raw_keys:
            raise ValueError("v2 cannot contain archive keys")
        descriptor, name = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".partial", dir=self.path.parent)
        self.temporary = Path(name)
        self.handle = os.fdopen(descriptor, "w+b")
        self.handle.write(bytes(HEADER_SIZE))
        self.records = []

    def add(self, raw_name, data, *, protect=False, cipher=128, compression=1):
        if len(data) > MAX_OUTPUT:
            raise ValueError("entry output exceeds 256 MiB limit")
        if protect:
            if self.version != 0x300:
                raise ValueError("protected entries require v3")
            from .protected import encode_entry
            packed = encode_entry(data, raw_name, cipher=cipher, compression=compression, keys=self.keys,
                                  key_id=next(iter(self.keys), 0))
            flags = 0x80
        else:
            packed = zlib.compress(data)
            flags = 1
        self.add_raw(raw_name, packed, len(data), flags)

    def add_raw(self, raw_name, payload, real_size, flags, *, compressed_size=None):
        if not raw_name or b"\0" in raw_name or len(raw_name) > 4096:
            raise ValueError("invalid raw filename")
        if len(self.records) >= MAX_ENTRIES:
            raise ValueError("too many entries")
        if flags & 0x80 and self.version != 0x300:
            raise ValueError("protected entries require v3")
        offset = self.handle.tell() - HEADER_SIZE
        if self.version == 0x200 and offset > 0xFFFFFFFF:
            raise ValueError("v2 offset exceeds 32 bits; use --version 3")
        compressed_size = len(payload) if compressed_size is None else compressed_size
        if not 0 <= compressed_size <= len(payload) <= MAX_PACKED or not 0 <= real_size <= MAX_OUTPUT:
            raise ValueError("invalid entry sizes")
        entry = Entry(len(self.records), raw_name, compressed_size, len(payload), real_size, flags, offset)
        if flags not in (0, 1, 2, 3, 5, 0x80) or (not entry.is_file and (compressed_size or payload or real_size)):
            raise ValueError("unsupported flags or nonempty directory")
        self.records.append((raw_name, compressed_size, len(payload), real_size, flags, offset))
        self.handle.write(payload)

    def _finish(self):
        relative = self.handle.tell() - HEADER_SIZE
        if self.version == 0x200 and relative > 0xFFFFFFFF:
            raise ValueError("v2 file table offset exceeds 32 bits; use --version 3")
        record_struct = struct.Struct("<IIIBQ" if self.version == 0x300 else "<IIIBI")
        table = bytearray()
        for name, *record in self.records:
            table.extend(name + b"\0" + record_struct.pack(*record))
        if len(table) > MAX_TABLE:
            raise ValueError("file table exceeds supported size")
        compressed = zlib.compress(table)
        if self.version == 0x300:
            self.handle.write(struct.pack("<I", len(self.raw_keys)))
        self.handle.write(struct.pack("<II", len(compressed), len(table)) + compressed + self.raw_keys)
        self.handle.seek(0)
        header = (b"Event Horizon\0c" if self.version == 0x300 else b"Master of Magic") + bytes(range(15))
        header += (struct.pack("<QI", relative, len(self.records)) if self.version == 0x300
                   else struct.pack("<III", relative, 0, len(self.records) + 7))
        self.handle.write(header + struct.pack("<I", self.version))
        self.handle.flush()
        os.fsync(self.handle.fileno())

    def __enter__(self):
        return self

    def __exit__(self, error_type, error, traceback):
        try:
            if error_type is None:
                self._finish()
                self.handle.close()
                # link is atomic and fails if the destination appeared meanwhile.
                os.link(self.temporary, self.path)
        finally:
            self.handle.close()
            self.temporary.unlink(missing_ok=True)
