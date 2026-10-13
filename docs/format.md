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

## Recovery and manifests

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

### Optional WAV repair

One known `data\wav\worm_tail_damage.wav` entry is truncated: its audio survives,
but seven metadata bytes and the zlib checksum are missing. Normal extraction
rejects it. `--repair-known-wav` accepts only the fingerprinted damaged input and
appends seven zero bytes to match the February 2026 reference, then verifies the
output hash. This does not prove the missing original bytes were zero.

The manifest records the repair and sets `lossless_complete: false`, even when
`complete` is true. Use `--resume --repair-known-wav` on an existing extraction.
See [repairs.py](../src/grf_extractor/repairs.py).

## Optional native decoder

Native mode compares decoding against a specific Windows client through Frida.
It requires **32-bit Windows Python 3.12** and the executable identified by
[client-profile.json](../src/grf_extractor/native/client-profile.json).
Other executable hashes or entry points are rejected.

1. Set `$research` to a working directory and `$clientSource` to the client directory.
2. Unpack [Python 3.12.10 win32](https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-win32.zip)
   into `$research\python32`. Enable `import site` and add `Libs` to `python312._pth`.
3. Copy this repository to `$research\tools` and download
   [pip.pyz](https://bootstrap.pypa.io/pip/pip.pyz) to `$research\pip.pyz`.
4. Copy `Ragexe.exe`, its top-level DLLs and manifests into `$research\client`.
   Leave GRFs, game configuration and GameGuard in the original directory.

```powershell
& "$research\python32\python.exe" "$research\pip.pyz" install `
  --target "$research\python32\Libs" "$research\tools[native]"
Invoke-WebRequest `
  'https://raw.githubusercontent.com/ergrelet/unlicense/95c8dc6a4324ff70c04bceda8bd166be6c5f0c73/unlicense/resources/frida.js' `
  -OutFile "$research\tools\unlicense-agent.js"
& "$research\python32\python.exe" -m grf_extractor `
  --client "$research\client\Ragexe.exe" `
  --archive "$clientSource\data.grf" `
  --unlicense-agent "$research\tools\unlicense-agent.js" `
  --output 'D:\data-grf-extracted'
```

The startup agent's hash is checked against the profile. The game's main thread
stays stopped at its original entry point while selected decoder callbacks run;
the isolated process is terminated afterward. Native addresses and calling
conventions are recorded in [native-layout.json](../src/grf_extractor/native/native-layout.json)
and [native-decoder.js](../src/grf_extractor/native/native-decoder.js).
