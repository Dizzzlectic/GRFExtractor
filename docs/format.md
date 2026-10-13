# Reading protected kRO GRF files

Protected kRO GRF entries can be decoded without running the game client.
The archive keys are stored after the compressed file table. The portable
decoder supports body ciphers `1`, `5`, `7`, `128` and `133`, with the stored
checksums and output hashes intact. Unknown formats are rejected.

The [source package](../src/grf_extractor/) separates the tool into:

- `archive.py`: archive tables, keys and ordinary entry decoding.
- `cli.py` and `output.py`: extraction, safe destinations and resumable manifests.
- `codecs/`: protected headers, archive keys, body ciphers and legacy DES.
- `native/`: optional client callbacks, executable profile and address notes.
- `repairs.py`: explicit, fingerprint-checked repair for one damaged WAV.

An extraction creates a sibling `<output>.manifest.json` with source metadata,
file sizes and SHA-256 hashes, format counts and failures. `protected_complete`
reports recovery of every protected entry; `complete` also requires every other
entry to succeed. `repairs` identifies reference-based repairs, and
`lossless_complete` requires completion without them. Ordinary extraction
rejects truncated streams, including the damaged WAV described below.

## Supported executable

Native calls use the `Ragexe.exe` identified by `client-profile.json`:

```text
SHA-256: 0c8586bf763053290163b9ce5e34bf08f43118032f8edb68a6139f4e307abe6c
Size:    20,060,160 bytes
Base:    0x400000
OEP:     0xf1cfd0
```

OEP means original entry point: the first instruction of the unpacked program.
The extractor rejects another executable hash or entry point. Another client
revision requires its own verified address profile. Portable header, footer and
body decoding does not run the executable, but still validates the stored
checksums and rejects unsupported formats.

## Environment and extraction

### Portable extraction

Use Python 3.11 or later. From the repository root, install the package in a
virtual environment:

```sh
python -m pip install .
grf-extract --portable --archive kRO/data.grf --output data-grf-extracted
```

This mode needs no executable, Windows runtime or Frida. It reads the original
archive and writes decoded files to a separate directory. The native mode below
remains useful for comparing a new format against the supported client.

### Native extraction

Use **32-bit Windows Python 3.12**. The embedded
[3.12.10 win32 package](https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-win32.zip)
is suitable. Set `$research` to a working directory and `$clientSource` to the
patched client directory. Expand Python under `$research\python32`, enable
`import site`, and add `Libs` to `python312._pth`.

Copy this repository into `$research\tools`. Install the package with its pinned native dependency
using the official [pip zip application](https://bootstrap.pypa.io/pip/pip.pyz):

```powershell
& "$research\python32\python.exe" "$research\pip.pyz" install `
  --target "$research\python32\Libs" `
  "$research\tools[native]"
```

Copy `Ragexe.exe`, its top-level DLLs and manifests into `$research\client`.
Leave GRFs, game configuration and GameGuard in the original client directory.
The startup agent comes from
[Unlicense](https://github.com/ergrelet/unlicense), pinned to commit
`95c8dc6a4324ff70c04bceda8bd166be6c5f0c73`:

```powershell
Invoke-WebRequest `
  'https://raw.githubusercontent.com/ergrelet/unlicense/95c8dc6a4324ff70c04bceda8bd166be6c5f0c73/unlicense/resources/frida.js' `
  -OutFile "$research\tools\unlicense-agent.js"
```

The extractor verifies this agent's SHA-256:
`831653c8a84fb16dd15497cafe5a83aefe34f2c50f68781f69c6b4eade21fef3`.
The main game thread stays blocked at OEP. Only selected cipher initializers and
native callbacks run through Frida; the isolated process is terminated afterward.
Original client files are read only.

To extract the archive into a **new** directory:

```powershell
& "$research\python32\python.exe" -m grf_extractor `
  --client "$research\client\Ragexe.exe" `
  --archive "$clientSource\data.grf" `
  --unlicense-agent "$research\tools\unlicense-agent.js" `
  --output 'D:\data-grf-extracted'
```

`--entry 'data\msgstringtable.csv'` restricts extraction to a named file;
repeat the option for several files. `--probe` selects representative protected
entries. `--resume` retries unfinished records without replacing successful files.
Resume requires the same archive hash, size, modification time and decoder mode;
native mode also requires the same client profile. It checks recorded outputs
against their sizes and hashes before retrying failures. Missing or changed
outputs require review. Any remaining failure or unaccounted record produces exit status 1; inspect
the manifest to distinguish source damage from a decoding failure.

A recovery manifest is written before extraction starts and checkpointed after
10,000 records or 60 seconds, checked between records. After abrupt process
termination, resume verifies recorded successes and re-decodes unfinished records.
An output written after the last checkpoint is accepted only if its bytes match
the freshly decoded content. Checkpoints cover process interruption, not guaranteed
power-loss recovery. Older runs that left no manifest require a fresh output directory.
Archive signatures and version-specific record counts are validated, and duplicate
or conflicting file/directory destinations are rejected before any extraction writes.
`protected_formats` counts successful decoding attempts, including retries after
an output-write failure; `protected_extracted` counts recorded output files.

The focused recovery, archive-validation and native-boundary checks need Python
3.11 or later and Node.js, without game files, Frida or cipher dependencies:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p test_extract.py
node --test tests/test_native_decoder.cjs
```

### Damaged WAV and explicit repair

The affected `data\wav\worm_tail_damage.wav` record declares 1,410 packed,
aligned and output bytes. Its zlib stored block requires 1,421 packed bytes,
but the next archive entry starts immediately after byte 1,410. Only 1,403
WAV bytes survive: all 1,278 audio-sample bytes are intact, while seven bytes
of the final software-name metadata and the four-byte zlib checksum are
missing. Reading past the entry would consume another file.

The working February 2026 copy matches every surviving WAV byte and ends
with seven zero metadata bytes. Other metadata completions are possible,
so this reference does not establish the missing original content.

`--repair-known-wav` explicitly reproduces that reference. It accepts only
the exact damaged filename, flags, lengths and payload SHA-256, then checks
the repaired output SHA-256. It does not relax checks for other files.
For an existing extraction, add `--resume --repair-known-wav` to the extraction
command. The manifest records the reference, original error, input/output
hashes and ambiguous metadata. A finished output can therefore report
`complete: true` and `lossless_complete: false`; the source GRF is unchanged.

Portable dependencies are pinned in `pyproject.toml`, including LZ4.
The message CSV contains two Base64-encoded UTF-8 columns: message
identifier and Korean text. Preserve row order and formatting placeholders when
translating it. GRF entries have no individual modification timestamps; output
file timestamps describe extraction, not patching.

## Archive layout and key block

The GRF header is 46 bytes. Offset 30 holds four little-endian `u32` values:
low table offset, high table offset, count field and version. For version
`0x300`, the table header starts at `(high << 32) + low + 46` and holds three
`u32` values: key-block length, compressed table length and uncompressed table
length. The zlib table follows these 12 bytes; the key block follows the table.
A zero key-block length is valid in older version 3 archives.

Each table record has a NUL-terminated filename followed by `<IIIBQ>`: packed
size, aligned size, output size, flags and 64-bit offset. Payload offsets are
relative to byte 46. Version `0x200` uses table offset `low+46`, an eight-byte
packed/unpacked table prefix, and `<IIIBI>` records.

Flags `1` contain zlib data; `3` and `5` add the older DES transforms. Stored flag
`0` entries are copied directly. Flag `0x80` uses the protected format below.

The supported key block has this layout:

| Offset | Field |
| --- | --- |
| 0 | Version/type bytes `01 01 00 00` |
| 4 | 64-bit Unix timestamp |
| 12 | Encrypted body length |
| 16 | XXH32 of the decrypted body |
| 20 | CHAM-encrypted key records |

Its body uses CHAM-128/128 CBC with **80 rounds and big-endian cipher words**,
matching the [Crypto++ CHAM implementation](https://github.com/weidai11/cryptopp/blob/master/cham.cpp).
The key and IV are the first and second 16-byte halves of
`SHA256(b"uf8E8qAwHthrLxiS")`:

```text
Key: 52f0d26525540cd55e2da13ee5c0dd3c
IV:  547e56e23a7b417b2b0283c17bea3394
```

The timestamp does not affect these values. After decryption and XXH32
validation, each 64-byte record contains a little-endian `u32` key ID and
60 bytes of parameter material. The live block contains four records. Native
registration stores a further masked representation of these records; use the
**footer plaintext**, rather than those masked map values, for portable decoding.

## Protected headers and parameters

Use the filename's **original bytes**, including backslashes and CP949 bytes.
Changing case, separators or encoding before hashing changes the body mask.
Native XXH3_128 bytes are low64 followed by high64, both little endian, rather
than the usual displayed digest order.

| Offset | Protected header field |
| --- | --- |
| 0 | Version byte `1` |
| 1 | Header cipher: `1`, `2`, `0x0f` or `0x71` |
| 4 | XXH32 of the decrypted 96-byte descriptor |
| 8 | 16-bit body cipher ID |
| 10 | Compression: `0` stored, `1` zlib, `2` LZ4 |
| 11 | Parameter flag: bit 0 mixes in the output hash |
| 12 | Padded body size |
| 16 | Compressed plaintext size, excluding padding |
| 20 | Final output size |
| 24 | Final output's 16-byte XXH3_128 |
| 40 | Archive key ID; `0` uses the header's own material |
| 44–103 | Parameter material for key ID `0` |

Only bytes `8:104` are encrypted in the header. Types `1`, `2` and `0x0f` use
AES-128 CBC with key `56fd7e712f6d36f55ca599e67b18107a`. Their IVs are respectively
`4ce8a1ae45b321607e4f26a4bb140c96`, XXH3_128 of the raw filename, and XXH3_128 of
the four clear checksum bytes.

Type `0x71` uses ThreeWay with 11 rounds and CFB feedback across 12-byte blocks.
Key: `ad61aedabf203e1dfe1db72b`; IV: `a095dfcfd04b74db027ede09`.
`threeway.py` follows Crypto++'s
[public-domain implementation](https://github.com/weidai11/cryptopp/blob/master/3way.cpp).

Prepare the callback buffer after validating the decoded header:

1. Select the 60-byte footer record by key ID, or header bytes `44:104` for ID `0`.
2. If flag bit 0 is set, XOR each byte with `output_hash[index % 16]`.
3. Append four zero bytes to form the 64-byte buffer.

Unknown parameter flags or missing key records are errors. `bodies.py` and
`native-decoder.js` implement the same preparation rule.

## Body decoding

The first 128 compressed body bytes are clear. For a longer body, the callback
receives only the tail. Tail length includes padding; compressed length excludes
it. After tail decoding, concatenate the clear prefix, discard padding using
header offset 16, and decompress according to offset 10.

Cipher **1** derives `M = XXH3_128(raw_filename, seed=output_size)`, in native
little-endian byte order. Its CHAM key is
`XXH3_128(parameters[0:60], seed=LE64(M[8:16]))` in the same byte order.
Decrypt complete blocks in the first 1,024 tail bytes using CHAM-128/128 CBC,
80 rounds, big-endian cipher words and the output hash as IV. Call the resulting
blocks `A`. For every complete tail block, XOR `A` with `M`, rotate its four
32-bit words right by one position, then XOR with the previous `A` block; the
initial previous block is the output hash. Residual bytes receive
`A XOR M_prefix XOR previous_A_prefix`, without the word rotation. The feedback
uses the intermediate block, before the final transform.

Ciphers **5** and **7** decrypt an AES-128 CBC prefix with PKCS#7 padding.
The prefix contains `min(compressed_tail_length, 1024)` plaintext bytes and
`(floor(prefix_length / 16) + 1) * 16` ciphertext bytes. Validate and remove its
padding. XOR the remaining tail with a repeating 16-byte IDEA-CBC mask, starting
the mask at index zero after the AES prefix.

| Cipher | AES key | AES IV | IDEA plaintext | IDEA key | IDEA IV |
| --- | --- | --- | --- | --- | --- |
| `5` | parameters `0:16` | `16:32` | output hash | filename hash | `48:56` |
| `7` | parameters `28:44` | `44:60` | filename hash | output hash | `52:60` |

The IDEA mask uses encryption. Removing AES padding shifts the remaining tail
left; applying the mask before AES decryption produces incorrect content.

Cipher **128** uses AES-128 CBC with parameter bytes `44:60` as key and `28:44`
as IV. If the tail is shorter than 3,072 bytes, decrypt all complete 16-byte
blocks. Otherwise, decrypt **only tail bytes `2048:3072`**, a 1,024-byte window.
Leave the other bytes untouched at this stage. Form a 16-byte mask by IDEA-CBC
**encryption** of the filename hash, using the output hash as key and parameter
bytes `49:57` as IV. XOR the mask repeatedly across the entire tail from index 0.

Cipher **133** uses RC6-20 CFB with parameter bytes `24:40` as key and `40:56`
as IV. Decrypt only complete 16-byte blocks in the first **1,024 tail bytes**.
Form its IDEA-CBC mask by encrypting the output hash with the filename hash as
key and parameter bytes `49:57` as IV. XOR that mask across the entire tail.
Partial blocks and bytes outside the RC6 prefix receive only this XOR.

Other body IDs require the supported executable's registered native callbacks
or a separately verified implementation. Every accepted protected file passes
descriptor XXH32, exact decompressed length, and final XXH3_128. The five portable
ciphers reproduce native behavior at their block, padding and processing-window
boundaries.

## Native calls and further inspection

Addresses refer to preferred image base `0x400000`; adjust them to the loaded
module base.

| Address | Role |
| --- | --- |
| `0x433450`, `0x433520` | Selected C++ cipher initializers |
| `0xf1b38e` | CRT exit registration; research process uses a no-op |
| `0x78ac80` | Decoder constructor (`thiscall`), object size `0xe8` |
| `0x78c800` | Header decoder (`thiscall`): filename hash, input, size, output header |
| `0x791030` | XXH3_128 (`cdecl`): destination, input, length |
| `0x6ca320`, `0x6ca350` | LZ4/zlib wrappers (`cdecl`): input, length, output, capacity |
| `0x78d510` | Native key registration (`thiscall`): empty string, zero, block, length |
| `0x787ed0`, `0x788ec0` | Body callbacks for `128` and `133` |

The callback registry at `0x14ff848` contains IDs
`1, 5, 6, 7, 8, 11, 128, 133, 256, 257, 262, 268, 269`. Its nodes are 16 bytes;
the separate per-decoder key map uses 76-byte nodes, with map key at offset 8
and packed value at offset 10. Body callbacks take nine `cdecl` arguments:

```text
raw filename, filename length, filename hash, parameter buffer,
full decoded header, tail input, padded tail length, tail output, compressed tail length
```

The full entry routine `0x78bf00` has protection checks that fail before parameter
preparation in an isolated process. Extraction calls the header decoder and body
callbacks separately, using portable key preparation. Research interventions
used to capture the original buffer are not required by the extractor.

For native inspection, use the official
[Unlicense v0.4.0 x86 release](https://github.com/ergrelet/unlicense/releases/download/0.4.0/unlicense-py3.11-x86.zip)
(ZIP SHA-256 `d6184e054ae04f83bd08e56e64d7bc550fdd716563c342ad0c9b9f9b0f3210ac`):

```powershell
$env:__COMPAT_LAYER = 'RUNASINVOKER'
& "$research\unlicense\unlicense.exe" "$research\client\Ragexe.exe" `
  --target_version=3 --no_imports=True --timeout=20 --verbose=True
```

This produces `unpacked_Ragexe.exe` while skipping TLS callbacks `0xf1c570` and
`0xf1ba50`. Native code and cipher tables are visible, but protected VM regions
are not ordinary x86 code. Use the original executable for runtime probes;
linear disassembly of those regions is misleading. Keep each probe in its own
isolated client directory and terminate only its recorded process IDs.

## Preservation and later integration

The [GRFEditor support branch](https://github.com/Dizzzlectic/GRFEditor/tree/version-3-grf-support)
decodes protected records and preserves their original payloads, filenames and
key block when saving or repacking. It does not encode new protected records.
Protected renames and incompatible conversions are refused; decoded content can
be copied into ordinary entries. A future client can change keys, formats or
native addresses, so explicit unsupported-format errors remain necessary.
