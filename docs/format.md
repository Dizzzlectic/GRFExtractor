# GRF format notes

See the [README](../README.md) for installation, extraction and tests.

## Supported formats

The reader accepts GRF v2/v3 archives, ordinary zlib entries, older DES entries
and protected entries with these formats:

| Component | Supported values |
| --- | --- |
| Header cipher | `1`, `2`, `0x0f`, `0x71` |
| Body cipher | `1`, `5`, `7`, `128`, `133` |
| Compression | `0` stored, `1` zlib, `2` LZ4 |
| Parameters | Inline or archive key record; optional output-hash mixing |

Unknown formats are rejected. Protected decoding validates the descriptor's
XXH32, declared lengths and final output's XXH3_128 before accepting a file.

## Archive layout

The 46-byte archive header contains four little-endian `u32` values at offset
30: `low`, `high`, `count` and `version`.

| Field | V2 (`0x200`) | V3 (`0x300`) |
| --- | --- | --- |
| Table offset | `low + 46` | `(high << 32) + low + 46` |
| Table prefix | Packed and unpacked sizes (`u32` each) | Key-block size, packed size, unpacked size (`u32` each) |
| Record count | `count - high - 7` | `count` |
| Record after NUL-terminated filename | `<IIIBI>` | `<IIIBQ>` |

Record fields are packed size, aligned size, output size, flags and payload
offset. Payload offsets are relative to byte 46. The table is zlib-compressed.
In v3, the key block follows it; a zero-length key block is valid.

Entry flags: `1` is zlib, `3` and `5` add legacy DES transforms, and `0x80`
selects protected decoding. Flag `0` entries with equal packed/output sizes
are treated as stored data. See [archive.py](../src/grf_extractor/archive.py).

### Archive keys

The key block begins with `01 01 00 00`, followed by a 64-bit timestamp,
encrypted-body length and plaintext XXH32. Its encrypted body starts at byte 20.
Each decoded 64-byte record contains a little-endian `u32` key ID and 60 bytes
of parameters.

Decryption uses CHAM-128/128 CBC, 80 rounds and big-endian cipher words. The key
and IV are the first and second halves of `SHA256(b"uf8E8qAwHthrLxiS")`;
the timestamp does not affect them. Use the decoded records directly, not the
masked representation stored by the native client.
See [footer.py](../src/grf_extractor/codecs/footer.py).

## Protected entries

Filename hashes must use the **original filename bytes**, including case,
backslashes and CP949 encoding. XXH3_128 is represented as low64 then high64,
both little endian, rather than displayed digest order.

### Header

The protected header is 104 bytes. Only bytes `8:104` are encrypted.

| Offset | Field |
| --- | --- |
| 0 | Version byte `1` |
| 1 | Header cipher ID |
| 4 | XXH32 of the decrypted 96-byte descriptor |
| 8 | Body cipher ID (`u16`) |
| 10 | Compression ID |
| 11 | Parameter flags; bit 0 enables output-hash mixing |
| 12 | Padded body size |
| 16 | Compressed plaintext size, excluding padding |
| 20 | Output size |
| 24 | Output XXH3_128 (16 bytes) |
| 40 | Archive key ID; `0` selects inline parameters |
| 44–103 | Inline parameters |

Header types `1`, `2` and `0x0f` use AES-128 CBC. Their IVs are respectively
a fixed constant, the filename hash and the hash of the four clear checksum
bytes. Type `0x71` uses ThreeWay CFB with 12-byte feedback blocks.
Keys, IVs and transforms are in [headers.py](../src/grf_extractor/codecs/headers.py)
and [threeway.py](../src/grf_extractor/codecs/threeway.py).

Select 60 parameter bytes from the archive key record or header bytes `44:104`.
If flag bit 0 is set, XOR them with the repeating output hash. Append four zero
bytes to make the callback buffer. Missing keys and unknown flags are errors.

### Body

The first 128 compressed bytes are clear. Decode the tail only when the
**compressed length**, excluding padding, exceeds 128. Then join prefix and
tail, trim to the declared compressed size and decompress.

| Cipher | Tail transform |
| --- | --- |
| `1` | CHAM-CBC over complete blocks in the first 1,024 bytes, followed by filename-seeded hash mixing and feedback across the tail. |
| `5`, `7` | AES-CBC prefix with PKCS#7 padding, then a repeating IDEA-derived mask over the remainder. |
| `128` | AES-CBC over complete blocks if the tail is shorter than 3,072 bytes; otherwise only bytes `2048:3072`. IDEA-derived mask over the entire tail. |
| `133` | RC6-20 CFB over complete blocks in the first 1,024 bytes; IDEA-derived mask over the entire tail. |

These are summaries; parameter offsets, padding and feedback order are defined
in [bodies.py](../src/grf_extractor/codecs/bodies.py). The
[synthetic fixtures](../tests/fixtures/README.md) cover cipher boundaries,
partial blocks, key selection and malformed inputs.
