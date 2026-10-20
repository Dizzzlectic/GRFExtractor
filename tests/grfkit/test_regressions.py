"""Regressions for archive safety, stream boundaries and raw-name round trips."""
import json
import os
from pathlib import Path
import struct
import zlib

import pytest

from grfkit.archive import Archive, Writer, WAV_NAME
from grfkit.cli import MANIFEST, main
from grfkit.legacy import encode_full, encode_header


def _write_archive(path, records, *, version=0x300):
    with Writer(path, version=version) as writer:
        for name, data in records:
            writer.add(name, data)


def _unsupported_nonempty_directory(path):
    payload = zlib.compress(b"important data")
    table = b"data\\important.txt\0" + struct.pack(
        "<IIIBQ", len(payload), len(payload), 14, 2, 0)
    compressed = zlib.compress(table)
    header = b"Event Horizon\0c" + bytes(range(15))
    header += struct.pack("<QII", len(payload), 1, 0x300)
    path.write_bytes(header + payload + struct.pack("<III", 0, len(compressed), len(table)) + compressed)


def test_verify_rejects_nonempty_record_without_supported_file_flag(tmp_path):
    source = tmp_path / "bad-flags.grf"
    _unsupported_nonempty_directory(source)
    # A nonempty, unsupported record must not disappear from verification.
    assert main(["verify", str(source)]) != 0


def test_repack_refuses_to_discard_nonempty_record_without_supported_file_flag(tmp_path):
    source = tmp_path / "bad-flags.grf"
    target = tmp_path / "repacked.grf"
    _unsupported_nonempty_directory(source)
    assert main(["repack", str(source), str(target)]) != 0
    assert not target.exists()


@pytest.mark.parametrize("version", ["2", "3"])
def test_extract_edit_pack_preserves_collision_content_and_new_names(tmp_path, version):
    source = tmp_path / "input.grf"
    records = [(b"data", b"root file"), (b"data\\Case", b"upper"),
               (b"data\\case", b"lower"), (b".grf-manifest.jsonl", b"reserved"),
               (b"data\\percent%2F.bin", b"literal percent"),
               (b"data\\bad\xff.bin", b"raw byte"), (b"empty", b"")]
    _write_archive(source, records)
    root = tmp_path / "extract"
    assert main(["extract", str(source), str(root)]) == 0
    rows = [json.loads(line) for line in (root / MANIFEST).read_text().splitlines()]
    files = rows[1:]
    assert len({row["path"].casefold() for row in files}) == len(records)
    for row, (_, data) in zip(files, records):
        assert (root / row["path"]).read_bytes() == data
    (root / files[1]["path"]).write_bytes(b"edited upper")
    # Renaming both manifest identity and physical path is explicit and must
    # produce a newly encoded entry under its intended raw archive filename.
    renamed = b"data\\renamed.bin"
    old = root / files[2]["path"]
    new = old.with_name("new-disk-name.bin")
    old.rename(new)
    files[2]["path"] = new.relative_to(root).as_posix()
    files[2]["raw_name"] = renamed.hex()
    with (root / MANIFEST).open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    (root / "added.bin").write_bytes(b"new asset")
    target = tmp_path / "repacked.grf"
    args = ["pack", str(root), str(target), "--version", version]
    if version == "3":
        args.append("--protect")
    assert main(args) == 0
    with Archive(target) as archive:
        contents = [(entry.raw_name, archive.read(entry)) for entry in archive.entries]
        expected = list(records)
        expected[1] = (records[1][0], b"edited upper")
        expected[2] = (renamed, records[2][1])
        assert contents == expected + [(b"added.bin", b"new asset")]


def test_existing_output_and_symlink_inputs_are_never_overwritten(tmp_path):
    root = tmp_path / "input"
    root.mkdir()
    original = root / "a"
    original.write_bytes(b"safe")
    target = tmp_path / "output.grf"
    target.write_bytes(b"existing")
    assert main(["pack", str(root), str(target)]) != 0
    assert target.read_bytes() == b"existing"
    target.unlink()
    outside = tmp_path / "outside"
    outside.write_bytes(b"private")
    (root / "link").symlink_to(outside)
    assert main(["pack", str(root), str(target)]) != 0
    assert not target.exists()
    assert outside.read_bytes() == b"private"


@pytest.mark.skipif(os.name == "nt", reason="Windows disallows literal backslashes in filenames")
def test_pack_rejects_new_disk_names_that_become_archive_traversal(tmp_path):
    root = tmp_path / "input"
    root.mkdir()
    # Backslashes are literal native filename bytes on Linux, but GRF treats
    # them as separators. This must not create an unextractable archive.
    (root / "data\\..\\escaped.txt").write_bytes(b"new asset")
    target = tmp_path / "bad-path.grf"
    assert main(["pack", str(root), str(target)]) != 0
    assert not target.exists()


def test_known_wav_repair_does_not_mask_other_damage_at_same_name(tmp_path):
    source = tmp_path / "different-damage.grf"
    damaged = zlib.compress(bytes(1403))[:-2]
    with Writer(source) as writer:
        writer.add_raw(WAV_NAME, damaged, 1410, 1)
    with Archive(source) as archive:
        with pytest.raises(ValueError):
            archive.read(archive.entries[0], repair_known_wav=True)
        assert archive.repaired_indices == set()


def test_independent_interop_sample_extract_edit_pack(tmp_path):
    sample = Path(__file__).resolve().parents[2] / "artifacts/interop-sample.grf"
    if not sample.exists():
        pytest.skip("independent interoperability sample not available")
    with Archive(sample) as archive:
        expected = [(e.raw_name, archive.read(e)) for e in archive.entries if e.is_file]
    root = tmp_path / "extract"
    assert main(["extract", str(sample), str(root)]) == 0
    target = tmp_path / "protected.grf"
    assert main(["pack", str(root), str(target), "--protect"]) == 0
    with Archive(target) as archive:
        actual = [(e.raw_name, archive.read(e)) for e in archive.entries if e.is_file]
    assert actual == expected


@pytest.mark.parametrize("flags", [1, 3, 5])
def test_declared_compressed_size_excludes_legitimate_outer_alignment(tmp_path, flags):
    data = b"alignment test" * 21
    packed = zlib.compress(data)
    aligned = packed + bytes(8 - len(packed) % 8)
    if flags == 3:
        aligned = encode_full(aligned, len(aligned), len(packed))
    elif flags == 5:
        aligned = encode_header(aligned, len(aligned))
    path = tmp_path / "aligned.grf"
    with Writer(path) as writer:
        writer.add_raw(b"data\\aligned", aligned, len(data), flags, compressed_size=len(packed))
    with Archive(path) as archive:
        assert archive.read(archive.entries[0]) == data


@pytest.mark.parametrize("flags", [1, 3, 5])
def test_rejects_nonzero_trailing_bytes_inside_declared_compressed_payload(tmp_path, flags):
    data = b"alignment test" * 21
    packed = zlib.compress(data) + b"unexplained trailing bytes"
    aligned = packed + bytes((-len(packed)) % 8)
    if flags == 3:
        aligned = encode_full(aligned, len(aligned), len(packed))
    elif flags == 5:
        aligned = encode_header(aligned, len(aligned))
    path = tmp_path / "trailing.grf"
    with Writer(path) as writer:
        writer.add_raw(b"data\\trailing", aligned, len(data), flags, compressed_size=len(packed))
    with Archive(path) as archive, pytest.raises(ValueError):
        archive.read(archive.entries[0])
