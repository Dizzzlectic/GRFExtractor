import importlib.util
from pathlib import Path

import pytest

from grfkit.archive import Writer
from grfkit.cli import main

spec = importlib.util.spec_from_file_location("verify_repack",
    Path(__file__).resolve().parents[2] / "validation/verify_repack.py")
validation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validation)


def test_manifest_comparison_checks_content_and_raw_order(tmp_path):
    original = tmp_path / "original.grf"
    with Writer(original) as writer:
        writer.add(b"data\\one", b"first", protect=True)
        writer.add(b"data\\two", b"second")
    manifest = tmp_path / "original.jsonl"
    assert main(["verify", str(original), "--manifest", str(manifest)]) == 0
    output = tmp_path / "repacked.grf"
    assert main(["repack", str(original), str(output), "--mode", "plain"]) == 0
    assert validation.verify(output, manifest)["matched_files"] == 2
    changed = tmp_path / "changed.grf"
    with Writer(changed) as writer:
        writer.add(b"data\\one", b"wrong")
        writer.add(b"data\\two", b"second")
    with pytest.raises(ValueError, match="content differs"):
        validation.verify(changed, manifest)
    reversed_archive = tmp_path / "reversed.grf"
    with Writer(reversed_archive) as writer:
        writer.add(b"data\\two", b"second")
        writer.add(b"data\\one", b"first")
    with pytest.raises(ValueError, match="identity differs"):
        validation.verify(reversed_archive, manifest)
