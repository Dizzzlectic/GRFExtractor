# SPDX-License-Identifier: GPL-3.0-or-later
"""Freeze small protected-GRF decoder inputs for a later native C++ oracle.

This tool captures/replays binary inputs with Python. It never starts Windows,
calls the native decoder, modifies a client, or writes to the source archive.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

import xxhash

from grfkit.archive import Archive, HEADER_SIZE
from grfkit.protected import (_header_transform, decode_entry, decode_keys,
                              encode_entry, encode_keys)

MAX_FIXTURE_BYTES = 10_000_000
_SCHEMA = "ragnarok-native-grf-oracle-1"
_NATIVE_ABI = {
    "validation_status": "partial-runtime-validation",
    "entry_body_acceptance": "unverified",
    "target": "20260930 Ragexe OEP-held scratch process",
    "calling_convention": "x86 __thiscall; context pointer in ECX",
    "context_constructor_va": "0x0078AC80",
    "context_minimum_bytes": 236,
    "entry_decoder_va": "0x0078BF00",
    "entry_decoder_stack_cleanup_bytes": 36,
    "entry_decoder_stack_arguments": ["rawNamePtr", "nameLen", "payloadPtr", "payloadLen",
                                       "scratchPtr", "scratchLen", "outPtr", "outCapacity", "flags"],
    "entry_decoder_return": "AL boolean; complete entry-body acceptance unverified",
    "key_loader_va": "0x0078D510",
    "key_loader_stack_arguments": ["outerNamePtr", "outerNameLen", "completeBlobPtr", "blobLen"],
    "key_loader_validation_status": "runtime-accepted",
    "key_loader_stack_cleanup_bytes": 16,
    "key_loader_argument_mapping": "First two words are caller-supplied outer name/span fields, "
                                   "not the footer revision. The complete raw blob includes its "
                                   "20-byte header. Runtime accepted an empty readable NUL span and "
                                   "the complete 276-byte live block; entry-body acceptance remains unverified.",
    "key_loader_callsite_evidence": {
        "archive_wrapper_va": "0x00C76B50", "loader_call_va": "0x00C76CCF",
        "context": "archive object + 0x54",
        "outer_name_words": "forwarded unchanged from wrapper [EBP+8], [EBP+0xC]",
        "complete_blob_words": "vector.begin, vector.end - vector.begin",
        "forwarding_wrapper_va": "0x00C76D50", "forwarding_call_va": "0x00C76D62",
        "empty_outer_span_call_va": "0x00E3D2B5",
        "empty_outer_name_pointer_va": "0x011F4B90", "empty_outer_name_length": 0,
        "revision_reader_va": "0x0078CB70",
        "revision_source": "little-endian signed-positive selection value at completeBlobPtr + 4",
    },
    "caution": "Initializer and VM-backed key loader/body continuation must execute normally. "
               "The fixture generator performs no native calls, and no complete native entry-body "
               "acceptance is established by the key-loader/header ABI checks.",
}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _xxh(data, seed=0):
    return xxhash.xxh3_128_intdigest(data, seed=seed).to_bytes(16, "little").hex()


def _codec(payload, name):
    header = _header_transform(payload[:104], name, True)
    cipher, compression, flags, padded, compressed, output = struct.unpack_from("<HBBIII", header, 8)
    return {"header_type": header[1], "body_cipher": cipher, "compression": compression,
            "parameter_flags": flags, "physical_body_size": padded,
            "compressed_plaintext_size": compressed, "output_size": output,
            "archive_key_id": struct.unpack_from("<I", header, 40)[0],
            "output_xxh3_128_le": header[24:40].hex(),
            "plaintext_header_hex": header.hex()}


def _group(codec):
    return codec["body_cipher"], codec["compression"], codec["header_type"]


def _keyblock_record(raw, path):
    keys = decode_keys(raw)
    result = {"file": path, "length": len(raw), "sha256": _sha(raw),
              "records": [{"id": key, "material_hex": value.hex()} for key, value in sorted(keys.items())]}
    if raw:
        low, high, length, checksum = struct.unpack_from("<IIII", raw, 4)
        result["header"] = {"prefix_hex": raw[:4].hex(), "timestamp_u64_low": low,
                            "timestamp_u64_high": high, "encrypted_body_length": length,
                            "decrypted_body_xxh32": checksum, "header_length": 20,
                            "encrypted_body_offset": 20}
    return result


def generate(archive_path: Path, destination: Path, *, synthetic_matrix=False):
    """Capture one small member per observed live group plus optional 425 matrix."""
    archive_path, destination = Path(archive_path), Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    files = {}
    keyblocks = {}
    cases = []
    matrix_cases = 0
    observed = Counter()

    def add_keys(label, raw):
        path = f"{label}/archive-keys.bin"
        files[path] = raw
        keyblocks[label] = _keyblock_record(raw, path)

    def add_case(label, name, payload, real_size, key_label, *, source=None,
                 accepted=True, error_contains=None, original_codec=None):
        codec = original_codec or _codec(payload, name)
        keys = decode_keys(files[keyblocks[key_label]["file"]])
        if accepted:
            decoded = decode_entry(payload, name, real_size, keys)
            expected = {"accepted": True, "decoded_length": len(decoded),
                        "decoded_sha256": _sha(decoded), "decoded_xxh3_128_le": _xxh(decoded)}
        else:
            try:
                decode_entry(payload, name, real_size, keys)
            except ValueError as error:
                if error_contains not in str(error):
                    raise ValueError(f"Negative fixture {label} failed at unexpected stage: {error}") from error
                expected = {"accepted": False, "python_error_contains": error_contains,
                            "python_error": str(error)}
            else:
                raise ValueError(f"Negative fixture {label} was unexpectedly accepted")
        payload_file, name_file = f"{label}/payload.bin", f"{label}/raw-name.bin"
        files[payload_file], files[name_file] = payload, name + b"\0"
        case = {"id": label, "kind": "protected-entry", "raw_name_hex": name.hex(),
                "raw_name_file": name_file, "filename_xxh3_128_le": _xxh(name),
                "seeded_filename_xxh3_128_le": _xxh(name, real_size),
                "payload_file": payload_file, "payload_length": len(payload),
                "payload_sha256": _sha(payload), "keyblock": key_label, "codec": codec,
                "expected": expected,
                "native_call": {"name_length": len(name), "payload_length": len(payload),
                                "scratch_capacity": max(len(payload), codec["physical_body_size"],
                                                        codec["compressed_plaintext_size"], real_size) + 4096,
                                "output_capacity": real_size, "flags": 0}}
        if original_codec is not None:
            case["codec_metadata_note"] = "Original valid header metadata before deliberate corruption"
        if source is not None:
            case["source"] = source
        cases.append(case)

    def capture_entry(archive, entry, label, key_label):
        payload = archive.payload(entry)[:entry.compressed_size]
        add_case(label, entry.raw_name, payload, entry.real_size, key_label,
                 source={"archive": "generated:interop/make_matrix.py" if key_label == "synthetic" else str(archive.path),
                         "entry_index": entry.index,
                         "flags": entry.flags, "archive_relative_offset": entry.offset,
                         "archive_absolute_offset": entry.offset + HEADER_SIZE})

    with Archive(archive_path) as archive:
        add_keys("live", archive.raw_keys)
        best = {}
        pet_talk = []
        for entry in archive.entries:
            if not entry.protected:
                continue
            # Read headers only while allocating the smallest representative.
            header = archive._read(HEADER_SIZE + entry.offset, 104)
            codec = _codec(header, entry.raw_name)
            group = _group(codec)
            observed[group] += 1
            score = (codec["compressed_plaintext_size"] <= 128, entry.compressed_size, entry.index)
            if group not in best or score < best[group][0]:
                best[group] = score, entry
            if entry.raw_name.replace(b"/", b"\\").lower().split(b"\\")[-1] == b"pettalktable.xml":
                pet_talk.append(entry)
        captured = set()
        for (cipher, compression, header), (_, entry) in sorted(best.items()):
            label = f"live/c{cipher}-z{compression}-h{header}"
            capture_entry(archive, entry, label, "live")
            captured.add(entry.index)
        for entry in pet_talk:
            if entry.index not in captured:
                capture_entry(archive, entry, f"live/pet-talk-table-{entry.index}", "live")
        source = {"path": str(archive.path), "length": archive.size, "version": archive.version,
                  "table_relative_offset": archive.table_offset - HEADER_SIZE,
                  "observed_protected_entries": sum(observed.values())}

    if synthetic_matrix:
        script = Path(__file__).resolve().parents[1] / "interop/make_matrix.py"
        with tempfile.TemporaryDirectory(prefix="ragnarok-native-grf-oracle-") as temporary:
            matrix_path = Path(temporary) / "matrix"
            subprocess.run([sys.executable, str(script), str(matrix_path)], check=True, capture_output=True, text=True)
            with Archive(matrix_path / "matrix.grf") as matrix:
                add_keys("synthetic", matrix.raw_keys)
                for entry in matrix.entries:
                    capture_entry(matrix, entry, f"synthetic/case-{entry.index:03d}", "synthetic")
                    matrix_cases += 1

    # Controlled negatives use synthetic content and deterministic inline keys.
    # Their malformed data never relies on live assets or native execution.
    if "synthetic" not in keyblocks:
        add_keys("synthetic", encode_keys({7: bytes(range(60))}))
    name = "data\\한글\\negative.bin".encode("cp949")
    material = bytes((i * 31 + 7) % 256 for i in range(60))
    short = encode_entry(b"native oracle output-hash check", name, cipher=128,
                         compression=0, header_type=2, flags=0, material=material)
    broken = bytearray(short)
    broken[4] ^= 1
    add_case("negative/header-checksum", name, bytes(broken), 31, "synthetic",
             accepted=False, error_contains="header checksum", original_codec=_codec(short, name))
    header = bytearray(_header_transform(short[:104], name, True))
    header[24] ^= 1
    struct.pack_into("<I", header, 4, xxhash.xxh32_intdigest(header[8:]))
    bad_hash = _header_transform(bytes(header), name, False) + short[104:]
    add_case("negative/output-hash", name, bad_hash, 31, "synthetic",
             accepted=False, error_contains="output hash", original_codec=_codec(short, name))
    padded = encode_entry(bytes(range(144)), name, cipher=5, compression=0,
                          header_type=2, flags=0, material=material)
    bad_pad = bytearray(padded)
    bad_pad[104 + 128 + 15] ^= 1
    add_case("negative/pkcs7-padding", name, bytes(bad_pad), 144, "synthetic",
             accepted=False, error_contains="PKCS#7", original_codec=_codec(padded, name))

    index = {"schema": _SCHEMA, "source": source, "native_abi": _NATIVE_ABI,
             "expectation_provenance": "Python codec checks; independent C# matrix interoperability "
                                       "was previously verified. No native entry-body acceptance is claimed.",
             "keyblocks": keyblocks,
             "observed_live_groups": [{"body_cipher": c, "compression": z, "header_type": h, "count": n}
                                      for (c, z, h), n in sorted(observed.items())],
             "synthetic_matrix_cases": matrix_cases, "cases": cases}
    files["index.json"] = (json.dumps(index, sort_keys=True, indent=2) + "\n").encode()
    total = sum(map(len, files.values()))
    if total >= MAX_FIXTURE_BYTES:
        raise ValueError(f"Fixture size {total} exceeds the strict {MAX_FIXTURE_BYTES}-byte budget")
    destination.mkdir(parents=True, exist_ok=False)
    for relative, data in files.items():
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as target:
            target.write(data)
    result = check(destination)
    result["fixture_bytes"] = total
    result["synthetic_matrix_cases"] = matrix_cases
    return result


def check(directory: Path):
    """Replay frozen binary inputs, checking the index and expected failures."""
    directory = Path(directory)

    def read(relative):
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Fixture path must remain inside its directory")
        target = directory / path
        if target.is_symlink() or any(p.is_symlink() for p in target.parents if p.is_relative_to(directory)):
            raise ValueError("Symlink fixture input is not supported")
        return target.read_bytes()

    index = json.loads((directory / "index.json").read_text())
    if index.get("schema") != _SCHEMA:
        raise ValueError("Unsupported native oracle fixture schema")
    total = sum(p.stat().st_size for p in directory.rglob("*") if p.is_file())
    if total >= MAX_FIXTURE_BYTES:
        raise ValueError("Native oracle fixture exceeds the strict size budget")
    keys = {}
    for label, value in index["keyblocks"].items():
        raw = read(value["file"])
        if len(raw) != value["length"] or _sha(raw) != value["sha256"]:
            raise ValueError("Archive keyblock SHA-256 or size mismatch")
        keys[label] = decode_keys(raw)
        if {record["id"]: bytes.fromhex(record["material_hex"]) for record in value["records"]} != keys[label]:
            raise ValueError("Archive keyblock records differ from index")
    accepted = rejected = 0
    ids = set()
    live_groups = set()
    for case in index["cases"]:
        if case["id"] in ids:
            raise ValueError("Duplicate fixture case ID")
        ids.add(case["id"])
        name = bytes.fromhex(case["raw_name_hex"])
        if read(case["raw_name_file"]) != name + b"\0":
            raise ValueError("Native raw name buffer differs from index")
        payload = read(case["payload_file"])
        if len(payload) != case["payload_length"] or _sha(payload) != case["payload_sha256"]:
            raise ValueError("Protected payload SHA-256 or size mismatch")
        if case["filename_xxh3_128_le"] != _xxh(name):
            raise ValueError("Filename hash differs from index")
        output_size = case["codec"]["output_size"]
        if case["seeded_filename_xxh3_128_le"] != _xxh(name, output_size):
            raise ValueError("Seeded filename hash differs from index")
        native = case["native_call"]
        if (native["name_length"] != len(name) or native["payload_length"] != len(payload)
                or native["output_capacity"] != output_size or native["flags"] != 0
                or not max(case["codec"]["physical_body_size"], case["codec"]["compressed_plaintext_size"])
                       <= native["scratch_capacity"] < MAX_FIXTURE_BYTES
                or not 0 <= output_size < MAX_FIXTURE_BYTES):
            raise ValueError("Native call lengths/capacities differ from bounded fixture buffers")
        expected = case["expected"]
        try:
            decoded = decode_entry(payload, name, output_size, keys[case["keyblock"]])
        except ValueError as error:
            if expected["accepted"] or expected["python_error_contains"] not in str(error):
                raise ValueError(f"Unexpected decoder rejection for {case['id']}: {error}") from error
            rejected += 1
        else:
            if not expected["accepted"]:
                raise ValueError(f"Malformed fixture was accepted: {case['id']}")
            if len(decoded) != expected["decoded_length"] or _sha(decoded) != expected["decoded_sha256"]:
                raise ValueError(f"Decoded output SHA-256 or size mismatch: {case['id']}")
            if _xxh(decoded) != expected["decoded_xxh3_128_le"]:
                raise ValueError("Decoded output XXH3 differs from index")
            accepted += 1
            if case["keyblock"] == "live":
                live_groups.add(_group(case["codec"]))
    if live_groups != {(g["body_cipher"], g["compression"], g["header_type"])
                      for g in index["observed_live_groups"]}:
        raise ValueError("Frozen cases do not cover all observed live algorithm groups")
    return {"accepted_cases": accepted, "rejected_cases": rejected,
            "observed_live_groups": len(live_groups), "fixture_bytes": total}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("generate")
    capture.add_argument("archive", type=Path)
    capture.add_argument("destination", type=Path)
    capture.add_argument("--synthetic-matrix", action="store_true")
    verify = commands.add_parser("check")
    verify.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    if args.command == "generate":
        result = generate(args.archive, args.destination, synthetic_matrix=args.synthetic_matrix)
    else:
        result = check(args.directory)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
