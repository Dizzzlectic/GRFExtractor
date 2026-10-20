import json
from pathlib import Path
import subprocess
import sys

import pytest

from grfkit.archive import Archive, Writer

def run(*args):
    return subprocess.run([sys.executable, "-m", "grfkit.cli", *map(str, args)], capture_output=True, text=True)


def test_extract_edit_pack_keeps_raw_names_and_collisions(tmp_path):
    original = tmp_path / "original.grf"
    names = [b"data\\Name.txt", b"data\\name.txt", "data\\한글.txt".encode("cp949")]
    with Writer(original) as writer:
        for name in names:
            writer.add(name, name * 20, protect=True)
    target = tmp_path / "extract"
    result = run("extract", original, target)
    assert result.returncode == 0, result.stderr
    rows = [json.loads(s) for s in (target / ".grf-manifest.jsonl").read_text().splitlines()]
    files = rows[1:]
    assert len(files) == 3
    assert len({r["path"].casefold() for r in files}) == 3
    (target / files[0]["path"]).write_bytes(b"edited content")
    new = tmp_path / "edited.grf"
    result = run("pack", target, new, "--protect")
    assert result.returncode == 0, result.stderr
    with Archive(new) as archive:
        assert [e.raw_name for e in archive.entries] == names
        assert archive.read(archive.entries[0]) == b"edited content"
        assert all(e.protected for e in archive.entries)
    result = run("verify", new)
    assert result.returncode == 0, result.stderr


def test_extract_rejects_traversal_before_writing(tmp_path):
    archive = tmp_path / "evil.grf"
    with Writer(archive) as writer:
        writer.add(b"..\\escaped", b"bad")
    target = tmp_path / "extract"
    result = run("extract", archive, target)
    assert result.returncode != 0
    assert not (tmp_path / "escaped").exists()
    assert not target.exists()


def test_repack_removes_protection_and_preserves_content(tmp_path):
    source = tmp_path / "source.grf"
    with Writer(source, keys={7: bytes(range(60))}) as writer:
        writer.add(b"data\\secret", b"SECRET" * 1000, protect=True)
        writer.add(b"data\\normal", b"NORMAL" * 1000)
    output = tmp_path / "out.grf"
    result = run("repack", source, output, "--mode", "plain")
    assert result.returncode == 0, result.stderr
    with Archive(output) as archive:
        assert len(archive.entries) == 2
        assert not any(e.protected for e in archive.entries)
        assert archive.read(archive.entries[0]) == b"SECRET" * 1000


def test_filtered_extraction_does_not_extract_other_assets(tmp_path):
    source = tmp_path / "source.grf"
    with Writer(source) as writer:
        writer.add(b"data\\one.txt", b"one")
        writer.add(b"data\\two.bin", b"two")
    target = tmp_path / "out"
    result = run("extract", source, target, "--match", "*.txt")
    assert result.returncode == 0, result.stderr
    assert (target / "data/one.txt").read_bytes() == b"one"
    assert not (target / "data/two.bin").exists()


def test_pack_refuses_symlinks_and_external_manifest_paths(tmp_path):
    source = tmp_path / "input"
    source.mkdir()
    outside = tmp_path / "private"
    outside.write_text("private")
    (source / "leak").symlink_to(outside)
    result = run("pack", source, tmp_path / "output.grf")
    assert result.returncode != 0
    (source / "leak").unlink()
    (source / ".grf-manifest.jsonl").write_text(
        json.dumps({"type": "archive"}) + "\n" +
        json.dumps({"path": "../private", "raw_name": b"x".hex()}) + "\n")
    result = run("pack", source, tmp_path / "output.grf")
    assert result.returncode != 0


def test_verify_reports_damage_and_nonzero_exit(tmp_path):
    source = tmp_path / "bad.grf"
    with Writer(source) as writer:
        writer.add(b"bad", b"A" * 200)
    data = bytearray(source.read_bytes())
    data[48] ^= 1
    source.write_bytes(data)
    manifest = tmp_path / "report.jsonl"
    result = run("verify", source, "--manifest", manifest)
    assert result.returncode != 0
    assert '"error"' in manifest.read_text()


@pytest.mark.parametrize("text", ['[]\n', '{"type":"archive"}\n[]\n',
                                   '{"type":"archive"}\n{"path":1,"raw_name":null}\n'])
def test_malformed_manifest_reports_error_without_creating_archive(tmp_path, text):
    source = tmp_path / "input"
    source.mkdir()
    (source / ".grf-manifest.jsonl").write_text(text)
    output = tmp_path / "output.grf"
    result = run("pack", source, output)
    assert result.returncode == 1
    assert result.stderr.startswith("error:")
    assert not output.exists()
