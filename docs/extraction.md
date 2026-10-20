# Extraction, verification and repacking

Run these commands from the repository root after installing the package as
shown in the [README](../README.md). Portable extraction requires no game
process, native profile or Windows runtime.

## Select and extract

```sh
grf inspect /path/to/data.grf
grf list /path/to/data.grf --match '*clientinfo*'
grf extract /path/to/data.grf extracted --resumable
grf extract /path/to/data.grf maps --match '*.gat' --match '*.gnd' --match '*.rsw'
grf extract /path/to/data.grf extracted --resume
```

Canonical `grf extract` uses portable decoding. Repeat `--match` for case-insensitive globs;
`*` also matches directory separators. The compatibility interface remains
`grf-extract --archive ARCHIVE --output OUTPUT --portable`; repeat `--entry`
for exact member selections. `python -m grf_extractor` invokes the same
resumable/native CLI and checkpoints by default. Canonical `grf extract` needs
`--resumable` to create a checkpoint; `--resume` continues an existing one.
See [native decoder](native.md) for exact-profile native requirements.

Fresh extraction requires a new destination. Absolute archive names and
traversal components are rejected before extraction. Names that collide under
case folding, reserved names and unsupported Windows characters receive distinct
portable paths. Existing unrelated files are never overwritten. File timestamps
reflect extraction because GRF entries have no per-entry modification times.

## Raw names and checkpoints

`<output>/.grf-manifest.jsonl` uses schema `grfkit-manifest-1` and preserves raw
filename bytes as hex, original flags, decoded lengths, SHA-256 hashes and actual
filesystem paths. Keep it with extracted content: packing uses its `raw_name`
and `path` fields to reconstruct original names, including collisions. Decoding
CP949 to display text does not replace these original bytes in protection hashes.

When resumability is enabled, the sibling `<output>.manifest.json` is a
separate resume checkpoint with schema
`grf-extractor-checkpoint-2`. It records archive identity, decoder mode, output
sizes/hashes, repairs and failures; file records bind to source entry index and
raw filename. `complete` reports recovery of the entire archive;
`protected_complete` reports all protected entries. Selections remain incomplete
for these whole-archive claims. `lossless_complete` additionally requires no
repairs.

`--resume` requires the same archive hash, size, modification time and decoder
mode. Native mode also requires the same client profile. It verifies recorded
outputs before retrying unfinished entries. Outputs written after the last
checkpoint are accepted only if they match freshly decoded content. Modified
outputs are rejected; preserve edits and pack them separately before resuming.
Old checkpoints without the current schema require a fresh extraction and are
not silently interpreted as current checkpoints.

Checkpoints are written before extraction and every 10,000 entries or 60 seconds,
checked between entries. They handle process interruption; power-loss recovery
is not guaranteed. A missing checkpoint requires fresh extraction. Remaining
failures or unaccounted entries yield exit status 1. `protected_formats` counts
successful attempts, including retries; `protected_extracted` counts recorded
output files. Creating or resuming a checkpoint hashes the full source for identity. Default
`grf extract`, metadata inspection, listing and selected verification avoid that
full-source hash; they still hash decoded outputs where applicable.

## Edit and pack

```sh
grf pack extracted edited.grf
grf pack extracted protected.grf --protect
```

Packing writes ordinary v3 by default. `--protect` newly encrypts entries with
header type 2 and body cipher 128; `--cipher` accepts `1`, `5`, `7`, `128`,
`133`. `--compression` accepts `0` stored, `1` zlib (default), or `2` raw LZ4.
The [protected API](protected-format.md) also exposes all header types and
archive key maps. New key blocks default to revision 1; explicit custom maps
need deliberate revision/merge management across mounted archives.

Edit files in place and keep the raw-name manifest. To rename an archive member,
change both its manifest `raw_name` hex and its filesystem `path`, or pack a
fresh directory without a manifest. Filename-dependent protection is recomputed
from the new raw name. Newly added files use CP949 unless `--encoding` specifies
another encoding. Missing manifest files, failed extraction records, unsafe
paths and symlinks stop packing.

Avoid full extraction by repacking directly:

```sh
grf repack /path/to/data.grf preserved.grf --mode preserve
grf repack /path/to/data.grf plain.grf --mode plain
grf repack /path/to/data.grf protected.grf --mode protected
```

Preserve mode validates decoded content and copies original payloads/key blocks;
plain mode emits ordinary zlib entries; protected mode encrypts every file,
including originally ordinary entries. Ordinary output supports `--version 2`;
its offsets must fit within 4 GiB. V3 uses 64-bit offsets. Writers build a
temporary sibling, publish on success and remove failed temporary files.
Output archive paths must be new.

## Verify content

```sh
grf verify /path/to/data.grf --match 'data/clientinfo.xml'
grf verify /path/to/data.grf --manifest artifacts/verified.jsonl
python validation/verify_repack.py plain.grf artifacts/verified.jsonl --summary artifacts/repack-checked.json
```

Verification streams one member at a time and returns nonzero for any decoding
failure. Reports require new paths. Protected integrity checks include header
checksum, padding, output length and XXH3; ordinary decoding requires a complete
zlib stream and exact length. SHA-256 records what was decoded, not an
independently known checksum for ordinary data. The repack comparator requires
the same raw record count, names and order, decoded lengths and SHA-256 hashes,
while permitting different compression/protection.

For a routine archive patch, inspect the header/table and verify only resources
needed by the current experiment. Size, whole-file hash and table-order changes
alone do not justify full-archive scans. Use regression fixtures for tool changes;
broaden validation for unsupported variants, a shared decoder/writer change,
widespread corruption or an explicit full-validation requirement.

## Repair the known truncated WAV

The damaged `data\\wav\\worm_tail_damage.wav` has a 1,410-byte compressed payload,
but decoding recovers only 1,403 of its declared 1,410 output bytes. Its complete
1,278-byte PCM chunk ends at byte 1,322; seven trailing metadata bytes are missing.
Normal extraction rejects the incomplete zlib stream.

`--repair-known-wav` appends exactly seven zero bytes. It applies only to the
exact filename, sizes, compressed-payload SHA-256
`df4f72d0eef4765118980484b2d2229cef815d432d4955dfdb0746b96d4d317c`, and checked
RIFF/chunk layout. Other damage is rejected. The archive remains unchanged.

This retains the surviving audio; it does not recover the original missing
metadata. The checkpoint records the repair and sets `lossless_complete: false`,
even when `complete` is true. Add `--resume --repair-known-wav` to retry this
member in an interrupted extraction. Pack/repack can then emit a valid ordinary
stream containing the repaired bytes. See the portable
[archive reader](../src/grfkit/archive.py) and extraction
[repair adapter](../src/grf_extractor/repairs.py).
