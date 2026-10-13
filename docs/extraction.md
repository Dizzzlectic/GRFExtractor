# Extraction and recovery

See the [README](../README.md) for installation and basic usage.

## Manifests and resume

`<output>.manifest.json` records archive identity, output sizes and SHA-256
hashes, format counts, repairs and failures. `complete` reports recovery of the
whole archive; `protected_complete` reports recovery of all protected entries.
Both remain false for `--entry` or `--probe` selections. `lossless_complete`
also requires no repairs.

`--resume` requires the same archive hash, size, modification time and decoder
mode; native mode also requires the same client profile. It verifies recorded
outputs before retrying unfinished entries. Files written after the last
checkpoint are accepted only when they match freshly decoded content.

Checkpoints are written before extraction and every 10,000 entries or 60 seconds,
checked between entries. They cover process interruption, not guaranteed
power-loss recovery. Missing manifests require a fresh extraction. Any remaining
failure or unaccounted entry produces exit status 1.

`protected_formats` counts successful decoding attempts, including retries;
`protected_extracted` counts recorded output files. Extracted file timestamps
reflect extraction, since GRF entries have no individual modification timestamps.

## Repairing a known truncated WAV

A known malformed `data\wav\worm_tail_damage.wav` entry contains 1,410
compressed bytes, but its declared DEFLATE block requires 1,421 bytes including
headers and checksum. Decoding recovers 1,403 WAV bytes containing all the audio
samples; seven trailing metadata bytes and the compressed stream's checksum
are missing. Normal extraction rejects this incomplete stream.

`--repair-known-wav` appends seven zero bytes to restore the declared WAV length.
It applies only to the exact damaged input identified by its filename, sizes
and SHA-256 hash, and verifies the repaired output hash. The source archive
remains unchanged.

This preserves the surviving audio but does not recover the missing original
metadata. The manifest records the repair and sets `lossless_complete: false`,
even when `complete` is true. Use `--resume --repair-known-wav` on an existing
extraction. See [repairs.py](../src/grf_extractor/repairs.py).

The problem was already discussed by GRF tool developers in
[May 2014](https://rathena.org/board/topic/95086-lessgrf-slim-down-your-grf/).
That discussion reports nonzero trailing metadata in an older copy; zero-filling
is a repair, not a reconstruction of those original bytes.
