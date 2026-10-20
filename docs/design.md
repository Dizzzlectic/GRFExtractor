# GRF tooling design

GRFExtractor provides a portable Python archive library and CLI, with optional
native decoding isolated behind a Windows/Frida bridge. Python 3.11+ with
PyCryptodome, xxhash and lz4 supplies standard primitives; local code implements
the GRF-specific CHAM, IDEA, RC6, ThreeWay and legacy DES transformations.
See [NOTICE](../NOTICE) for reference revision and license attribution.

`grfkit/archive.py` owns container parsing and writing: headers, file tables,
raw filename bytes, offsets and archive key blocks. `grfkit/protected.py` owns
protected encoding/decoding, while `grfkit/legacy.py` owns older DES transforms.
`grfkit/cli.py` supplies inspection, listing, verification and pack/repack.
The `grf_extractor` package supplies extraction checkpoints and output handling;
its compatibility modules use the same portable parser and codec. Native profile
and callback behavior remain in `grf_extractor/native/`.

Every protected decode checks header checksum, bounds, cipher padding, output
length and content hash. Ordinary and legacy entries require complete streams
and exact decoded lengths. Unknown variants fail explicitly. The only opt-in
repair is the exact damaged WAV described in [extraction](extraction.md).

Extraction preserves raw names and collision-safe paths in a JSONL manifest.
Resume uses a separate versioned checkpoint and verifies outputs before reuse.
Pack restores manifest names; new entries use the requested text encoding.
Repacking makes preservation, removal and new encoding of protection explicit.
Writers build a temporary sibling archive, publish only after success, remove
failed temporary output and refuse to overwrite existing destinations.

The two independent synthetic fixture suites remain separate: the existing
fixture bundle validates decoder behavior, while `tests/grfkit/` covers parser,
writer, malformed input, encoder vectors and raw-name round trips. Optional
upstream comparison and the independent [C# reader](../interop/README.md)
provide additional checks without becoming runtime dependencies. Native fixture
preparation and Frida decoding are distinct workflows; portable/C# success does
not establish native body decoding, startup or gameplay.

Full archive comparison streams one member at a time and compares decoded
content, raw name bytes and record order where appropriate. It permits different
compression and encryption. Routine resource experiments use metadata and
selected-entry validation; broad/full scans are reserved for format changes,
shared decoder/writer impact or evidence of widespread corruption. Generated
archives, reports and private inputs stay bounded and outside source history.
