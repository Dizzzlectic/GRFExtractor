"""Tests for frozen native-decoder oracle input preparation; no native launch."""
import json
from pathlib import Path

import pytest

from grfkit.archive import Writer
from grfkit.protected import encode_entry
from validation.native_grf_oracle import generate, check, MAX_FIXTURE_BYTES


def _source(path):
    keys = {7: bytes(range(60))}
    with Writer(path, keys=keys) as writer:
        for index, (cipher, compression, header) in enumerate(((128, 2, 2), (5, 0, 1), (128, 2, 2))):
            data = bytes((i * 13 + 23) % 256 for i in range(1500 + index * 100))
            name = f"data\\한글\\sample-{index}.bin".encode("cp949")
            payload = encode_entry(data, name, cipher=cipher, compression=compression,
                                   header_type=header, key_id=7, keys=keys)
            writer.add_raw(name, payload, len(data), 0x80)


def test_frozen_capture_replays_without_source_and_includes_negative_cases(tmp_path):
    source = tmp_path / "source.grf"
    _source(source)
    output = tmp_path / "oracle"
    generated = generate(source, output)
    source.unlink()
    checked = check(output)
    assert checked["accepted_cases"] == 2
    assert checked["rejected_cases"] == 3
    assert checked["observed_live_groups"] == 2
    assert generated["fixture_bytes"] < MAX_FIXTURE_BYTES
    index = json.loads((output / "index.json").read_text())
    assert index["native_abi"]["validation_status"] == "partial-runtime-validation"
    assert index["native_abi"]["entry_body_acceptance"] == "unverified"
    assert index["native_abi"]["key_loader_validation_status"] == "runtime-accepted"
    assert index["native_abi"]["key_loader_stack_arguments"] == [
        "outerNamePtr", "outerNameLen", "completeBlobPtr", "blobLen"]
    assert index["native_abi"]["key_loader_stack_cleanup_bytes"] == 16
    assert index["native_abi"]["key_loader_callsite_evidence"]["loader_call_va"] == "0x00C76CCF"
    for case in index["cases"]:
        raw = bytes.fromhex(case["raw_name_hex"])
        assert (output / case["raw_name_file"]).read_bytes() == raw + b"\0"
        assert case["native_call"]["name_length"] == len(raw)
        assert case["native_call"]["output_capacity"] == case["codec"]["output_size"]
    with pytest.raises(FileExistsError):
        generate(tmp_path / "missing-source", output)


def test_full_synthetic_matrix_is_small_and_deterministic(tmp_path):
    source = tmp_path / "source.grf"
    _source(source)
    output = tmp_path / "oracle"
    generated = generate(source, output, synthetic_matrix=True)
    checked = check(output)
    assert generated["synthetic_matrix_cases"] == 425
    assert checked["accepted_cases"] == 427
    assert checked["rejected_cases"] == 3
    assert sum(p.stat().st_size for p in output.rglob("*") if p.is_file()) < MAX_FIXTURE_BYTES


def test_capture_detects_mutated_binary_inputs(tmp_path):
    source = tmp_path / "source.grf"
    _source(source)
    output = tmp_path / "oracle"
    generate(source, output)
    index = json.loads((output / "index.json").read_text())
    target = output / index["cases"][0]["payload_file"]
    value = bytearray(target.read_bytes())
    value[-1] ^= 1
    target.write_bytes(value)
    with pytest.raises(ValueError, match="payload SHA-256"):
        check(output)
