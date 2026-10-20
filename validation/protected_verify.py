"""Stream-verify protected entries and emit reproducible synthetic-safe evidence."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import time

from grfkit.archive import Archive
from grfkit.protected import _header_transform, decode_entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("summary", type=Path)
    args = parser.parse_args()
    started = time.monotonic()
    input_hash = hashlib.sha256()
    with args.archive.open("rb") as source:
        for block in iter(lambda: source.read(4 * 1024 * 1024), b""):
            input_hash.update(block)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    groups = Counter()
    count = total = 0
    combined = hashlib.sha256()
    errors = []
    with Archive(args.archive) as archive, args.manifest.open("x", encoding="utf-8") as manifest:
        for entry in archive.entries:
            if not entry.protected:
                continue
            record = {"index": entry.index, "raw_name_hex": entry.raw_name.hex(),
                      "real_size": entry.real_size, "compressed_size": entry.compressed_size}
            try:
                payload = archive.payload(entry)[:entry.compressed_size]
                output = decode_entry(payload, entry.raw_name, entry.real_size, archive.keys)
                header = _header_transform(payload[:104], entry.raw_name, True)
                cipher, compression = struct.unpack_from("<HB", header, 8)
                record.update(cipher=cipher, compression=compression, header_type=header[1],
                              sha256=hashlib.sha256(output).hexdigest(), verified=True)
                groups[(cipher, compression, header[1])] += 1
                count += 1
                total += len(output)
                combined.update(output)
            except (ValueError, OSError) as error:
                record.update(verified=False, error=str(error))
                errors.append({"index": entry.index, "error": str(error)})
            manifest.write(json.dumps(record, sort_keys=True) + "\n")
            if (count + len(errors)) % 5000 == 0:
                print(f"{count} protected entries verified, {len(errors)} errors", flush=True)
        summary = {"archive": str(args.archive), "archive_size": archive.size,
                   "input_sha256": input_hash.hexdigest(), "archive_key_count": len(archive.keys),
                   "verified_entries": count, "verified_output_bytes": total,
                   "concatenated_output_sha256": combined.hexdigest(),
                   "groups": [{"cipher": c, "compression": z, "header_type": h, "count": n}
                              for (c, z, h), n in sorted(groups.items())],
                   "errors": errors, "elapsed_seconds": round(time.monotonic() - started, 3)}
    with args.summary.open("x", encoding="utf-8") as target:
        json.dump(summary, target, indent=2, sort_keys=True)
        target.write("\n")
    print(json.dumps(summary, sort_keys=True), flush=True)
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
