import hashlib
import struct
import zlib

import pytest

from grfkit.archive import Archive, Writer


def fixture(path, version=0x300, kind=1, content=b"small example" * 30,
            payload=None, real_size=None):
    payload = zlib.compress(content) if payload is None else payload
    offset_format = "Q" if version == 0x300 else "I"
    table = b"data\\test.txt\0" + struct.pack(
        "<IIIB" + offset_format, len(payload), len(payload),
        len(content) if real_size is None else real_size, kind, 0)
    packed = zlib.compress(table)
    header = b"Master of Magic" + bytes(range(15))
    header += (struct.pack("<QI", len(payload), 1) if version == 0x300
               else struct.pack("<III", len(payload), 0, 8))
    header += struct.pack("<I", version)
    path.write_bytes(header + payload + (bytes(4) if version == 0x300 else b"")
                     + struct.pack("<II", len(packed), len(table)) + packed)
    return content


@pytest.mark.parametrize("version", [0x200, 0x300])
def test_reads_independent_modern_fixture(tmp_path, version):
    path = tmp_path / "fixture.grf"
    data = fixture(path, version)
    with Archive(path) as archive:
        assert archive.version == version
        assert archive.entries[0].raw_name == b"data\\test.txt"
        assert archive.read(archive.entries[0]) == data


def test_stored_file_without_file_bit(tmp_path):
    path = tmp_path / "stored.grf"
    fixture(path, kind=0, content=b"PNG123", payload=b"PNG123")
    with Archive(path) as archive:
        assert archive.entries[0].is_file
        assert archive.read(archive.entries[0]) == b"PNG123"


@pytest.mark.parametrize("version", [0x200, 0x300])
def test_writer_roundtrip_names_and_content(tmp_path, version):
    path = tmp_path / "output.grf"
    name = "data\\한글.txt".encode("cp949")
    with Writer(path, version=version) as writer:
        writer.add(name, b"contents" * 100)
        writer.add(b"data\\empty.txt", b"")
    with Archive(path) as archive:
        assert [e.raw_name for e in archive.entries] == [name, b"data\\empty.txt"]
        assert archive.read(archive.entries[0]) == b"contents" * 100
        assert archive.read(archive.entries[1]) == b""
    with pytest.raises(FileExistsError):
        with Writer(path):
            pass


def test_writer_failure_does_not_publish(tmp_path):
    path = tmp_path / "partial.grf"
    with pytest.raises(ValueError):
        with Writer(path) as writer:
            writer.add(b"ok", b"content")
            raise ValueError("failure halfway")
    assert not path.exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("payload,real", [(zlib.compress(b"A" * 5000), 4),
                                          (zlib.compress(b"hello")[:-2], 5)])
def test_ordinary_inflate_rejects_overrun_and_incomplete(tmp_path, payload, real):
    path = tmp_path / "bad.grf"
    fixture(path, payload=payload, real_size=real)
    with Archive(path) as archive:
        with pytest.raises(ValueError):
            archive.read(archive.entries[0])


def test_truncated_and_hostile_table_sizes(tmp_path):
    path = tmp_path / "bad.grf"
    fixture(path)
    data = bytearray(path.read_bytes())
    data[30:38] = struct.pack("<Q", 2**50)
    path.write_bytes(data)
    with pytest.raises(ValueError):
        Archive(path)


def test_v3_offsets_beyond_4gib(tmp_path):
    path = tmp_path / "large.grf"
    relative = 2**32 + 17
    content = b"large offset"
    packed = zlib.compress(content)
    table = b"data\\large\0" + struct.pack("<IIIBQ", len(packed),len(packed),len(content),1,relative)
    pt = zlib.compress(table)
    with path.open("wb") as f:
        f.write(b"Master of Magic" + bytes(range(15))
                + struct.pack("<QII", relative+len(packed), 1, 0x300))
        f.seek(46 + relative)
        f.write(packed + struct.pack("<III",0,len(pt),len(table)) + pt)
    with Archive(path) as archive:
        assert archive.read(archive.entries[0]) == content


def test_rejects_bad_flags_and_names_at_write(tmp_path):
    with pytest.raises(ValueError):
        with Writer(tmp_path / "bad.grf") as writer:
            writer.add(b"bad\0name", b"a")


def test_equal_compressed_and_real_sizes_still_decodes_valid_zlib(tmp_path):
    data = b"a" * 11
    packed = zlib.compress(data)
    assert len(packed) == len(data)
    path = tmp_path / "equal.grf"
    fixture(path, content=data, payload=packed)
    with Archive(path) as archive:
        assert archive.read(archive.entries[0]) == data


def test_extensionless_equal_length_file_stays_an_ordinary_file(tmp_path):
    path = tmp_path / "extensionless.grf"
    with Writer(path) as writer:
        writer.add(b"data\\extensionless", b"a" * 11)
    with Archive(path) as archive:
        entry = archive.entries[0]
        assert entry.flags == 1
        assert archive.read(entry) == b"a" * 11


def test_writer_rejects_inconsistent_archive_keys(tmp_path):
    from grfkit.protected import encode_keys
    path = tmp_path / "badkeys.grf"
    with pytest.raises(ValueError):
        with Writer(path, keys={7: bytes(60)}, raw_keys=encode_keys({8: bytes(60)})) as writer:
            writer.add(b"data\\test", b"example" * 100, protect=True)
    assert not path.exists()


def test_writer_derives_keys_from_raw_keyblock(tmp_path):
    from grfkit.protected import encode_keys
    path = tmp_path / "rawkeys.grf"
    with Writer(path, raw_keys=encode_keys({7: bytes(60)})) as writer:
        assert writer.keys == {7: bytes(60)}
        writer.add(b"data\\test", b"example", protect=True)
    with Archive(path) as archive:
        assert archive.read(archive.entries[0]) == b"example"


@pytest.mark.parametrize("sizes,relative", [
    ((9, 8, 1), 0),
    ((1, 300 * 1024 * 1024 + 1, 1), 0),
    ((1, 1, 256 * 1024 * 1024 + 1), 0),
    ((1, 1, 1), 2**40),
])
def test_rejects_invalid_entry_metadata_before_payload_decode(tmp_path, sizes, relative):
    # Metadata-only callers must reject hostile records without reading payloads
    # or allocating the enormous sizes declared in the synthetic table.
    path = tmp_path / "invalid-entry.grf"
    payload = b"x"
    table = b"data\\invalid\0" + struct.pack("<IIIBQ", *sizes, 1, relative)
    packed = zlib.compress(table)
    header = b"Master of Magic" + bytes(range(15)) + struct.pack("<QII", len(payload), 1, 0x300)
    path.write_bytes(header + payload + struct.pack("<III", 0, len(packed), len(table)) + packed)
    with pytest.raises(ValueError, match="entry"):
        Archive(path)
