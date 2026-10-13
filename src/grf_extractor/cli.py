"""Extract GRF files with portable ciphers or the supported native decoder."""

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import time
import zlib

from .archive import MAX_OUTPUT_SIZE, MAX_PACKED_SIZE, read_entries, read_archive_keys, decode_ordinary
from .codecs.decoder import PortableDecoder
from .native.decoder import NativeDecoder, load_profile
from .output import destination, sha256, write_atomic

CHECKPOINT_ENTRIES = 10000
CHECKPOINT_SECONDS = 60


def probe_entries(archive, entries):
    groups = collections.defaultdict(list)
    with archive.open("rb") as source:
        for entry in entries:
            name, _packed, aligned, _real, flags, offset = entry
            if flags != 128:
                continue
            source.seek(offset)
            groups[source.read(4)].append(entry)
    chosen = {}
    for group in groups.values():
        ordered = sorted(group, key=lambda item: item[2])
        sample = ordered[:3] + [ordered[index * (len(ordered) - 1) // 11] for index in range(12)]
        for entry in sample:
            chosen[entry[0]] = entry
    for entry in entries:
        if entry[0].lower().replace(b"\\", b"/") in {
            b"data/msgstringtable.csv", b"data/cardprefixnametable.txt",
            b"data/luafiles514/lua files/skillinfoz/skillinfolist.lub",
        }:
            chosen[entry[0]] = entry
    return list(chosen.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, help="Isolated Ragexe.exe copy (native mode)")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New extraction directory")
    parser.add_argument("--unlicense-agent", type=Path, help="Pinned Frida startup agent (native mode)")
    parser.add_argument("--portable", action="store_true",
                        help="Decode supported formats without Windows, Frida or the executable")
    parser.add_argument("--probe", action="store_true", help="Only representative protected entries")
    parser.add_argument("--entry", action="append", help="Extract only a named entry; repeat as needed")
    parser.add_argument("--resume", action="store_true", help="Recover unfinished records from an extraction checkpoint")
    parser.add_argument("--repair-known-wav", action="store_true",
                        help="Repair the exact known truncated WAV to match a dated reference; recorded as non-lossless")
    args = parser.parse_args()
    profile = None
    mode = "portable" if args.portable else "native"
    if not args.portable:
        if args.client is None or args.unlicense_agent is None:
            parser.error("Native mode requires --client and --unlicense-agent")
        profile = load_profile()
        if os.name != "nt":
            parser.error("Use Windows Python for the native decoder, or select --portable")
        if args.client.name != "Ragexe.exe" or sha256(args.client) != profile["sha256"]:
            parser.error("Executable does not match the supported client profile")
        if args.client.parent == args.archive.parent:
            parser.error("Client must be an isolated copy outside the original client directory")
    if args.output.exists() and not args.resume:
        parser.error("Output directory already exists; choose a new directory")
    try:
        entries = read_entries(args.archive)
    except (OSError, ValueError, zlib.error) as error:
        parser.error(str(error))
    all_entry_count = len(entries)
    protected_entry_count = sum(entry[4] == 128 for entry in entries)
    if args.entry:
        requested = {name.lower().replace("\\", "/") for name in args.entry}
        entries = [entry for entry in entries if entry[0].decode("cp949").lower().replace("\\", "/") in requested]
        if len(entries) != len(requested):
            parser.error("One or more requested entries were not found")
    if args.probe:
        entries = probe_entries(args.archive, entries)
    # One record must own each destination. Check the complete selection before
    # writing, including on resume: an identical existing file is not a second record.
    entry_paths = {}
    destinations = set()
    try:
        for entry in entries:
            target = destination(args.output, entry[0])
            key = os.path.normcase(str(target.resolve()))
            if key in destinations:
                raise ValueError(f"Duplicate extraction path: {entry[0]!r}")
            destinations.add(key)
            entry_paths[entry[0]] = target.relative_to(args.output).as_posix()
        for key in destinations:
            if any(str(parent) in destinations for parent in Path(key).parents):
                raise ValueError(f"Conflicting file/directory extraction path: {key}")
    except (OSError, ValueError, UnicodeError) as error:
        parser.error(str(error))
    selected_entry_count = len(entries)
    manifest_path = args.output.with_name(args.output.name + ".manifest.json")
    if manifest_path.exists() and not args.resume:
        parser.error("Output manifest already exists; choose a new output or use --resume")
    manifest = {
        "archive": args.archive.name,
        "archive_size": args.archive.stat().st_size,
        "archive_mtime_ns": args.archive.stat().st_mtime_ns,
        "archive_sha256": sha256(args.archive),
        "client_sha256": profile["sha256"] if profile else None,
        "decoder_mode": mode,
        "probe": args.probe,
        "selection": args.entry,
        "entries": len(entries),
        "extracted": 0,
        "failures": [],
        "files": {},
        "repairs": [],
    }
    if args.resume:
        try:
            previous = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            parser.error(f"Cannot read resume manifest: {error}")
        if previous.get("decoder_mode", "native") != mode:
            parser.error("Resume source or selection mismatch: decoder_mode")
        for field in ("archive", "archive_size", "archive_mtime_ns", "archive_sha256", "client_sha256", "probe", "selection", "entries"):
            if previous.get(field) != manifest[field]:
                parser.error(f"Resume source or selection mismatch: {field}")
        if previous.get("extracted") != len(previous.get("files", {})):
            parser.error("Resume manifest success count mismatch")
        source_records = {entry_paths[e[0]]: e for e in entries}
        for relative, record in previous["files"].items():
            try:
                entry = source_records[relative]
                target = destination(args.output, relative.encode("cp949"))
                valid = (record["size"] == entry[3] and record["flags"] == entry[4]
                         and target.is_file() and target.stat().st_size == record["size"]
                         and sha256(target) == record["sha256"])
            except (OSError, ValueError, UnicodeError, KeyError, TypeError):
                valid = False
            if not valid:
                parser.error(f"Resume recorded output is missing, modified or unsafe: {relative}")
        # Reconcile against the source selection, rather than trusting that the
        # old failure list remembered every unfinished record.
        entries = [entry for entry in entries if entry_paths[entry[0]] not in previous["files"]]
        manifest = previous
        manifest["decoder_mode"] = mode
        manifest["failures"] = []
        manifest.setdefault("repairs", [])
    decoder = None
    pending = {entry[0] for entry in entries}
    started = time.monotonic()
    previous_formats = {(item["header"], item["cipher"], item["compression"]): item["count"]
                        for item in manifest.get("protected_formats", [])}

    def checkpoint():
        # Keep pending records in the on-disk snapshot without adding them to
        # this run's failures. A crash can leave at most one interval to retry;
        # files written after the last checkpoint are re-decoded and compared.
        snapshot = dict(manifest)
        snapshot["extracted"] = len(manifest["files"])
        snapshot["failures"] = manifest["failures"] + [
            {"name_hex": name.hex(), "error": "Not processed: extraction interrupted"}
            for name in sorted(pending)]
        counts = collections.Counter(previous_formats)
        if decoder is not None:
            counts.update(decoder.metadata_counts)
        snapshot["protected_formats"] = [
            {"header": key[0], "cipher": key[1], "compression": key[2], "count": count}
            for key, count in sorted(counts.items())]
        snapshot["complete"] = (snapshot["extracted"] == all_entry_count and not snapshot["failures"]
                                and not args.probe and not args.entry)
        snapshot["lossless_complete"] = snapshot["complete"] and not manifest["repairs"]
        snapshot["protected_entries"] = protected_entry_count
        snapshot["protected_extracted"] = sum(item["flags"] == 128 for item in manifest["files"].values())
        snapshot["protected_complete"] = (snapshot["protected_extracted"] == protected_entry_count
                                          and not args.probe and not args.entry)
        write_atomic(manifest_path,
                     (json.dumps(snapshot, ensure_ascii=True, indent=2) + "\n").encode("utf-8"),
                     replace=True)

    args.output.mkdir(parents=True, exist_ok=args.resume)
    checkpoint()  # Recoverable state exists before any file or native decoder is opened.
    last_checkpoint = time.monotonic()
    try:
        archive_keys = read_archive_keys(args.archive)
        decoder = PortableDecoder(archive_keys) if args.portable else NativeDecoder(
            args.client, args.unlicense_agent, profile, archive_keys)
        with args.archive.open("rb") as source:
            for index, (name, packed, aligned, real, flags, offset) in enumerate(entries, 1):
                try:
                    repair = None
                    target = destination(args.output, name)
                    source.seek(offset)
                    payload_size = packed if args.portable and flags == 128 else aligned
                    if args.portable and flags == 128 and (real > MAX_OUTPUT_SIZE or packed > MAX_PACKED_SIZE):
                        raise ValueError("Protected entry exceeds supported size limit")
                    payload = source.read(payload_size)
                    if len(payload) != payload_size:
                        raise ValueError("Truncated entry")
                    if flags == 128:
                        plain = decoder.decode(name, real, payload)
                    else:
                        plain, repair = decode_ordinary(name, packed, aligned, real, flags, payload,
                                                        allow_repair=args.repair_known_wav)
                    if len(plain) != real:
                        raise ValueError("Extracted size mismatch")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    output_hash = hashlib.sha256(plain).hexdigest()
                    if args.resume and (target.exists() or target.is_symlink()):
                        if not target.is_file() or target.stat().st_size != real or sha256(target) != output_hash:
                            raise ValueError("Resume target exists and differs from freshly decoded content")
                    else:
                        write_atomic(target, plain)
                    relative = target.relative_to(args.output).as_posix()
                    manifest["files"][relative] = {
                        "size": real, "sha256": output_hash, "flags": flags,
                    }
                    if repair is not None:
                        repair["path"] = relative
                        manifest["repairs"].append(repair)
                    manifest["extracted"] = len(manifest["files"])
                except Exception as error:
                    failure = {"name_hex": name.hex(), "error": str(error).splitlines()[0]}
                    manifest["failures"].append(failure)
                    print("Failed:", name, failure["error"], flush=True)
                pending.discard(name)
                if index % CHECKPOINT_ENTRIES == 0 or time.monotonic() - last_checkpoint >= CHECKPOINT_SECONDS:
                    checkpoint()
                    last_checkpoint = time.monotonic()
                if index % 1000 == 0 or index == len(entries):
                    print(f"{index}/{len(entries)}: {manifest['extracted']} extracted, "
                          f"{len(manifest['failures'])} failed, {time.monotonic() - started:.1f}s", flush=True)
    finally:
        try:
            checkpoint()
        finally:
            if decoder is not None:
                decoder.close()
    return 0 if not manifest["failures"] and len(manifest["files"]) == selected_entry_count else 1
