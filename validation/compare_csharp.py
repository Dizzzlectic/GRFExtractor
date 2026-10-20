"""Compare GRFEditor interop JSONL output with a grf verification manifest."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("csharp_output", type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    expected = {}
    with args.manifest.open(encoding="utf-8-sig") as source:
        header = json.loads(next(source))
        for line in source:
            row = json.loads(line)
            if "error" in row:
                raise ValueError("source manifest contains a decoding error")
            key = row["name"].replace("/", "\\").casefold()
            if key in expected:
                raise ValueError("logical filename collision; C# cannot prove raw-record preservation")
            expected[key] = (row["size"], row["sha256"])
    seen = set()
    total = 0
    with args.csharp_output.open(encoding="utf-8-sig") as source:
        for line in source:
            row = json.loads(line)
            key = row["path"].replace("/", "\\").casefold()
            if key in seen or expected.get(key) != (row["size"], row["sha256"]):
                raise ValueError(f"duplicate or differing C# content: {row['path']!r}")
            seen.add(key)
            total += row["size"]
    if len(seen) != len(expected) or len(expected) != header["files"]:
        raise ValueError("C# output does not contain every source file")
    summary = {"csharp_output": str(args.csharp_output), "matched_files": len(seen),
               "decoded_bytes": total, "errors": 0}
    if args.summary:
        with args.summary.open("x", encoding="utf-8") as output:
            json.dump(summary, output, indent=2)
            output.write("\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
