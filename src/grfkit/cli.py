"""Disk workflows for GRF extraction and repacking. SPDX-License-Identifier: GPL-3.0-or-later"""

import argparse
from collections import Counter
from contextlib import nullcontext
import fnmatch
import hashlib
import json
from pathlib import Path
import sys
import time
import unicodedata

from .archive import Archive, Writer, WAV_NAME

MANIFEST = ".grf-manifest.jsonl"


def emit(row, handle=sys.stdout):
    print(json.dumps(row, ensure_ascii=True), file=handle, flush=True)


def _segment(value):
    out = ""
    for char in value:
        code = ord(char)
        if 0xDC80 <= code <= 0xDCFF:
            out += f"%{code - 0xDC00:02X}"
        elif char in '<>:"/\\|?*%' or code < 32 or code == 127:
            out += "".join(f"%{byte:02X}" for byte in char.encode("utf-8"))
        else:
            out += char
    while out.endswith((" ", ".")):
        out = out[:-1] + f"%{ord(out[-1]):02X}"
    if out.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        out = "%" + out.encode("utf-8").hex()
    if len(out.encode("utf-8")) > 180:
        out = out.encode("utf-8")[:120].decode("utf-8", "ignore") + "~" + hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()[:16]
    return out


def _parts(name):
    name = name.replace("\\", "/")
    parts = name.split("/")
    if not parts or any(p in ("", ".", "..") for p in parts) or ":" in parts[0]:
        raise ValueError(f"unsafe archive/manifest path: {name!r}")
    return parts


def portable_paths(entries):
    """Allocate both directories and files case-insensitively for Windows reuse."""
    directories = {(): ()}
    used = {MANIFEST.casefold()}
    result = {}
    for entry in entries:
        parts = _parts(entry.name)
        parent = ()
        for depth, part in enumerate(parts):
            original = tuple(parts[:depth + 1])
            is_dir = depth < len(parts) - 1
            if is_dir and original in directories:
                parent = directories[original]
                continue
            name = _segment(part)
            candidate = parent + (name,)
            key = unicodedata.normalize("NFC", "/".join(candidate)).casefold()
            suffix = 0
            while key in used:
                suffix += 1
                candidate = parent + (name + f"~grf{entry.index}-{suffix}",)
                key = unicodedata.normalize("NFC", "/".join(candidate)).casefold()
            used.add(key)
            parent = candidate
            if is_dir:
                directories[original] = candidate
        result[entry.index] = "/".join(parent)
    return result


def selected(archive, patterns):
    return [e for e in archive.entries if e.is_file and
            (not patterns or any(fnmatch.fnmatchcase(e.name.casefold(), p.replace("\\", "/").casefold()) for p in patterns))]


def metadata(archive):
    files = [e for e in archive.entries if e.is_file]
    return {"type": "archive", "format": "grfkit-manifest-1", "version": archive.version,
            "archive_size": archive.size, "records": len(archive.entries), "files": len(files),
            "protected": sum(e.protected for e in files), "decoded_bytes": sum(e.real_size for e in files),
            "flags": {hex(k): v for k, v in Counter(e.flags for e in archive.entries).items()},
            "archive_keys": len(archive.keys)}


def record(entry, data=None, *, path=None, error=None, repaired=False):
    row = {"index": entry.index, "raw_name": entry.raw_name.hex(), "name": entry.name,
           "flags": entry.flags, "size": entry.real_size}
    if data is not None:
        row.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
    if path is not None:
        row["path"] = path
    if error is not None:
        row["error"] = str(error)
    if repaired:
        row["repair"] = "known-wav-seven-zero-bytes"
    return row


def progress(count, total, start):
    if count % 5000 == 0 or count == total:
        print(f"{count}/{total} entries; {time.monotonic() - start:.1f}s", file=sys.stderr, flush=True)


def inspect_command(args):
    with Archive(args.archive) as archive:
        emit(metadata(archive))
        if args.command == "list":
            for entry in selected(archive, args.match):
                emit(record(entry))
    return 0


def read_command(args):
    """Verify selected payloads without materializing an extraction tree."""
    with Archive(args.archive) as archive:
        entries = selected(archive, args.match)
        context = Path(args.manifest).open("x", encoding="utf-8") if args.manifest else nullcontext(None)
        errors = repaired = total = 0
        start = time.monotonic()
        with context as manifest:
            if manifest:
                emit(metadata(archive), manifest)
            for count, entry in enumerate(entries, 1):
                try:
                    data = archive.read(entry, repair_known_wav=args.repair_known_wav)
                    fixed = entry.index in archive.repaired_indices
                    row = record(entry, data, repaired=fixed)
                    total += len(data)
                    repaired += int(fixed)
                except (ValueError, OSError) as error:
                    errors += 1
                    row = record(entry, error=error)
                    emit(row, sys.stderr)
                if manifest:
                    emit(row, manifest)
                progress(count, len(entries), start)
        emit({"checked": len(entries), "errors": errors, "repaired": repaired, "decoded_bytes": total,
              "seconds": round(time.monotonic() - start, 3)})
        return int(errors != 0)


def _input_path(root, relative):
    parts = _parts(relative)
    path = root
    for part in parts:
        path /= part
        if path.is_symlink():
            raise ValueError(f"symlink input is not supported: {path}")
    if not path.is_file():
        raise ValueError(f"missing input file: {path}")
    return path


def pack_command(args):
    root = Path(args.directory)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("input must be an existing directory, not a symlink")
    manifest_path = root / MANIFEST
    rows = []
    if manifest_path.exists():
        if manifest_path.is_symlink():
            raise ValueError("symlink manifest")
        with manifest_path.open(encoding="utf-8") as handle:
            header = json.loads(next(handle))
            if not isinstance(header, dict) or header.get("type") != "archive":
                raise ValueError("invalid extraction manifest")
            for line in handle:
                row = json.loads(line)
                if not isinstance(row, dict) or not isinstance(row.get("path"), str) or not isinstance(row.get("raw_name"), str):
                    raise ValueError("invalid extraction manifest file record")
                if "error" in row:
                    raise ValueError("manifest contains failed extraction; refusing incomplete pack")
                rows.append((bytes.fromhex(row["raw_name"]), _input_path(root, row["path"])))
    seen = {path.relative_to(root).as_posix() for _, path in rows}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlink input is not supported: {path}")
        relative = path.relative_to(root).as_posix()
        if path.is_file() and relative != MANIFEST and relative not in seen:
            rows.append((relative.replace("/", "\\").encode(args.encoding), path))
    # Resolve all paths before creating the writer; an output inside the input
    # is not recursively included in the new archive.
    for raw_name, _ in rows:
        _parts(raw_name.decode("cp949", "surrogateescape"))
    start = time.monotonic()
    with Writer(args.output, version=args.version) as writer:
        for count, (name, path) in enumerate(rows, 1):
            if path.stat().st_size > 256 * 1024 * 1024:
                raise ValueError(f"input exceeds 256 MiB: {path}")
            writer.add(name, path.read_bytes(), protect=args.protect, cipher=args.cipher, compression=args.compression)
            progress(count, len(rows), start)
    emit({"written": len(rows), "output": str(args.output), "version": args.version, "protected": args.protect})
    return 0


def repack_command(args):
    start = time.monotonic()
    with Archive(args.archive) as archive:
        version = args.version or archive.version
        preserve = args.mode == "preserve"
        if preserve and version != archive.version and any(e.protected for e in archive.entries):
            raise ValueError("preserving protection requires v3; use --mode plain to convert")
        context = Path(args.manifest).open("x", encoding="utf-8") if args.manifest else nullcontext(None)
        with context as manifest, Writer(args.output, version=version,
                keys=archive.keys if preserve else {}, raw_keys=archive.raw_keys if preserve else None) as writer:
            if manifest:
                emit(metadata(archive), manifest)
            count = 0
            for entry in archive.entries:
                if not entry.is_file:
                    writer.add_raw(entry.raw_name, b"", 0, entry.flags)
                    continue
                data = archive.read(entry, repair_known_wav=args.repair_known_wav)
                fixed = entry.index in archive.repaired_indices
                if preserve and not fixed:
                    writer.add_raw(entry.raw_name, archive.payload(entry), entry.real_size, entry.flags,
                                   compressed_size=entry.compressed_size)
                else:
                    writer.add(entry.raw_name, data, protect=args.mode == "protected", cipher=args.cipher,
                               compression=args.compression)
                if manifest:
                    emit(record(entry, data, repaired=fixed), manifest)
                count += 1
                progress(count, len(archive.entries), start)
    emit({"written": count, "output": str(args.output), "mode": args.mode,
          "seconds": round(time.monotonic() - start, 3)})
    return 0


def _version(text):
    if text not in ("2", "3"):
        raise argparse.ArgumentTypeError("version must be 2 or 3")
    return int(text) * 0x100


def parser():
    root = argparse.ArgumentParser(description="Extract and repack kRO protected GRF v3 archives")
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("inspect", "list", "verify", "extract", "repack"):
        sub = commands.add_parser(name)
        sub.add_argument("archive", type=Path)
        if name in ("list", "verify", "extract"):
            sub.add_argument("--match", action="append", help="case-insensitive glob on paths, repeatable")
        if name in ("verify", "extract", "repack"):
            sub.add_argument("--repair-known-wav", action="store_true")
        if name in ("verify", "repack"):
            sub.add_argument("--manifest", type=Path)
        if name == "extract":
            sub.add_argument("destination", type=Path)
            sub.add_argument("--resumable", action="store_true", help="Hash source identity and save resume checkpoints")
            sub.add_argument("--resume", action="store_true", help="Continue a versioned extraction checkpoint")
        if name == "repack":
            sub.add_argument("output", type=Path)
            sub.add_argument("--mode", choices=("preserve", "plain", "protected"), default="preserve")
            sub.add_argument("--version", type=_version, metavar="{2,3}")
            sub.add_argument("--cipher", type=int, choices=(1, 5, 7, 128, 133), default=128)
            sub.add_argument("--compression", type=int, choices=(0, 1, 2), default=1)
    sub = commands.add_parser("pack")
    sub.add_argument("directory", type=Path)
    sub.add_argument("output", type=Path)
    sub.add_argument("--protect", action="store_true")
    sub.add_argument("--version", type=_version, metavar="{2,3}", default=0x300)
    sub.add_argument("--cipher", type=int, choices=(1, 5, 7, 128, 133), default=128)
    sub.add_argument("--compression", type=int, choices=(0, 1, 2), default=1)
    sub.add_argument("--encoding", default="cp949")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command in ("inspect", "list"):
            return inspect_command(args)
        if args.command == "verify":
            return read_command(args)
        if args.command == "extract":
            from grf_extractor.cli import main as extract_main
            options = ["--portable", "--archive", str(args.archive), "--output", str(args.destination)]
            for pattern in args.match or []:
                options.extend(["--match", pattern])
            if args.resume:
                options.append("--resume")
            if args.repair_known_wav:
                options.append("--repair-known-wav")
            return extract_main(options, checkpoint_enabled=args.resumable or args.resume)
        if args.command == "pack":
            return pack_command(args)
        return repack_command(args)
    except (ValueError, OSError, KeyError, StopIteration, UnicodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
