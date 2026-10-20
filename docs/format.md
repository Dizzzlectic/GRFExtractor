# GRF archive format

This guide describes the portable container reader and writer. See
[extraction](extraction.md) for commands and [protected format](protected-format.md)
for the exact protected payload transforms.

## Supported containers

The 46-byte archive header accepts `Master of Magic` and `Event Horizon`
signatures. Four little-endian `u32` words at offset 30 are `low`, `high`,
`count` and `version`.

| Field | V2 (`0x200`) | V3 (`0x300`) |
| --- | --- | --- |
| Table offset | `low + 46` | `(high << 32) + low + 46` |
| Table prefix | Packed and unpacked sizes (`u32` each) | Key-block size, packed size, unpacked size (`u32` each) |
| Record count | `count - high - 7` | `count` |
| Record after NUL-terminated filename | `<IIIBI>` | `<IIIBQ>` |

Record fields are compressed size, aligned size, output size, flags and payload
offset. Payload offsets are relative to byte 46. The table is zlib-compressed;
the v3 key block follows it. A zero-length key block is valid. A GRFEditor-style
mislabeled v2 container is recognized when version is `0x300` and the upper
24 bits of `high` are nonzero. Writers emit unambiguous v2/v3 layouts.

V2 offsets cannot exceed 4 GiB; oversized output fails explicitly. V3 uses
64-bit offsets. Original filename bytes and each raw record remain distinct,
even when names collide under case folding. Display names use CP949 with
surrogate escaping; filename-dependent protection always hashes the raw bytes.
See [archive.py](../src/grfkit/archive.py).

## Entry decoding

| Flags | Treatment |
| --- | --- |
| `1` | Ordinary zlib |
| `3`, `5` | Legacy GRF DES transform, then zlib |
| `0x80` | Protected header/body decoding |
| `0` | Stored file when positive compressed/output sizes agree; otherwise an empty directory record |
| `2` | Empty directory record only |

Unsupported flags and nonempty directory records fail instead of disappearing
from verification. The decoder separates declared compressed bytes from outer
alignment padding. Zlib streams must finish at the declared output length,
without unexplained trailing compressed bytes. Legacy transformation runs on
aligned data before the compressed-size boundary is applied.

The [legacy DES implementation](../src/grfkit/legacy.py) covers header-only
and mixed modes. Protected decoding supports header IDs `1`, `2`, `0x0f`,
`0x71`; body ciphers `1`, `5`, `7`, `128`, `133`; and stored, zlib or raw LZ4
compression. Inline parameters and archive key records are supported, including
optional output-hash mixing. Unknown variants are rejected.

## Integrity and limits

Protected entries must satisfy the descriptor XXH32, payload bounds, cipher
padding, decompression length and output XXH3-128. These hashes detect corruption;
they do not provide cryptographic authentication. Ordinary data has exact stream
and length checks but no independently known content hash in the container.
Verification manifests record SHA-256 of the decoded bytes actually read.

Individual decoded entries are limited to 256 MiB, tables to 512 MiB and archives
to 500,000 records. No proprietary input is required for the synthetic
[fixture bundle](../tests/fixtures/README.md) or the separate
[grfkit regressions](../tests/grfkit/). GRF 1.x and general native-client
compatibility are outside the portable format contract.
