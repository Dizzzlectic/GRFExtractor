"""Compare every decoded archive member with a prior grf verify manifest."""
import argparse
import hashlib
import json
from pathlib import Path
import time

from grfkit.archive import Archive


def verify(archive_path, manifest_path):
    start = time.monotonic()
    count = total = 0
    combined = hashlib.sha256()
    with Archive(archive_path) as archive, Path(manifest_path).open(encoding="utf-8") as manifest:
        header = json.loads(next(manifest))
        if header.get("format") != "grfkit-manifest-1" or header.get("records") != len(archive.entries):
            raise ValueError("manifest format or raw record count differs")
        for entry in archive.entries:
            if not entry.is_file:
                continue
            try:
                row = json.loads(next(manifest))
            except StopIteration as error:
                raise ValueError("manifest is missing archive members") from error
            if "error" in row or row.get("index") != entry.index or row.get("raw_name") != entry.raw_name.hex():
                raise ValueError(f"manifest member identity differs at index {entry.index}")
            data = archive.read(entry)
            digest = hashlib.sha256(data).hexdigest()
            if row.get("size") != len(data) or row.get("sha256") != digest:
                raise ValueError(f"decoded content differs at index {entry.index}: {entry.raw_name!r}")
            combined.update(data)
            count += 1
            total += len(data)
            if count % 10000 == 0:
                print(f"Compared {count} files", flush=True)
        if any(line.strip() for line in manifest):
            raise ValueError("manifest contains extra archive members")
    return {"archive": str(archive_path), "matched_files": count, "decoded_bytes": total,
            "concatenated_output_sha256": combined.hexdigest(), "errors": 0,
            "seconds": round(time.monotonic() - start, 3)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    try:
        summary = verify(args.archive, args.manifest)
    except (ValueError, OSError, StopIteration) as error:
        parser.exit(1, f"error: {error}\n")
    if args.summary:
        with args.summary.open("x", encoding="utf-8") as output:
            json.dump(summary, output, indent=2)
            output.write("\n")
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
