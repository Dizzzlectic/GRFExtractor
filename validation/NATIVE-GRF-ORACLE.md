# Frozen inputs for the native protected-GRF decoder

`native_grf_oracle.py` prepares binary buffers and a JSON index for a later test
of the actual 20260930 Ragexe C++ decoder. It does not run Windows, start or
modify a client, or claim that the native decoder accepts the fixtures. Python
replay establishes the expected contents and controlled rejection cases.

## Reproduce and check

From the repository root:

```sh
python validation/native_grf_oracle.py generate \
  /mnt/c/kRO/data.grf artifacts/native-grf-oracle --synthetic-matrix
python validation/native_grf_oracle.py check \
  artifacts/native-grf-oracle
python -m pytest -q \
  validation/test_native_grf_oracle.py
```

The destination must be new. Generation reads only entry headers while selecting
one small live member per observed `(body cipher, compression, header type)`
combination, preferring compressed bodies longer than 128 bytes so the body
transform actually runs. It also captures `PetTalkTable.xml` when present.
`--synthetic-matrix` invokes the existing `interop/make_matrix.py` in a temporary
directory and captures its complete 425-case matrix. Temporary matrix files are
removed automatically. Without that option only the live representatives and
three small synthetic negatives are captured.

Generated fixtures are bounded by a strict 10,000,000-byte limit. They remain
independently replayable after the source archive and temporary synthetic
archive are unavailable. Live case counts and names depend on the supplied archive.

The synthetic matrix covers all five body ciphers, four header types, three
compression modes, both parameter flags, inline/footer keys and 65 boundary
cases, including empty bodies. The same matrix can be checked with the separate
[GRFEditor C# interoperability harness](../interop/README.md). C# comparison
does not establish native-client compatibility.

## Index and buffers

`index.json` uses schema `ragnarok-native-grf-oracle-1`. Each case provides:

| Field | Meaning |
| --- | --- |
| `id` | Stable case label, such as `live/c128-z2-h2` |
| `raw_name_hex`, `raw_name_file` | Original encoded name bytes and a binary buffer containing those bytes plus one terminating NUL |
| `payload_file`, `payload_length`, `payload_sha256` | Exact protected entry payload, including its 104-byte header; excludes outer archive alignment |
| `filename_xxh3_128_le`, `seeded_filename_xxh3_128_le` | Native-order filename hash and filename hash seeded by final output size |
| `keyblock` | Reference to the matching raw archive key block and parsed material records |
| `codec` | Header/body variants, parameter flags, key ID, physical/compressed/output sizes, output XXH3 and decrypted header bytes |
| `expected` | Python acceptance or rejection; valid cases include decoded length, SHA-256 and XXH3 |
| `native_call` | Name/payload lengths, scratch/output capacities and flags zero; pointers must be allocated by the native harness |
| `source` | Original archive index and both relative and absolute file offsets; synthetic entries identify their generator |

The `keyblocks` dictionary provides each complete raw binary block, its size and
SHA-256, parsed IDs and their 60-byte material, and the split between the clear
20-byte header and encrypted body. It also records the low/high words of the
eight-byte timestamp/revision field at offset 4. Those words are not the native
key loader's first two arguments. `0x0078CB70` reads that value separately; the
archive wrappers require a signed-positive, nonzero revision and can select the
newest revision across mounted archives before distributing its complete block
to every archive context.

## Native ABI status

The addresses and call shape in `native_abi` come from static analysis of the
held unpacked process and its archive caller, with bounded runtime confirmation
of context construction, key-loader arguments and header decoding. They are
marked `partial-runtime-validation`; complete entry-body acceptance remains
unverified. The fixture generator itself performs no native calls.

- Context constructor: `0x0078AC80`, x86 `__thiscall`, context in ECX; reserve at
  least `0xEC` bytes and run its normal initialization.
- Key loader: `0x0078D510`, context in ECX, four stack words in order
  `outerNamePtr, outerNameLen, completeBlobPtr, blobLen`, with callee cleanup of
  16 bytes. The first two words are forwarded caller-supplied name/span fields;
  they are not the footer revision. The third points to the complete raw block,
  including its 20-byte header. This mapping is established by static machine
  instructions and a successful native call with an empty readable NUL name,
  length zero and the complete 276-byte live block. That call returned AL=1
  without crossing its canaries; it does not establish entry-body acceptance.
- Entry decoder: `0x0078BF00`, context in ECX, nine stack words in order
  `rawNamePtr, nameLen, payloadPtr, payloadLen, scratchPtr, scratchLen, outPtr,
  outCapacity, flags`; callee cleanup is `RET 0x24`. The archive caller uses AL
  as a boolean. Name length excludes the terminating NUL. Header bytes and
  filename hashes have matched captured fixtures through the native header
  helper; this is separate from full body decoding.

Each suggested scratch capacity is the maximum of payload, physical body,
compressed body and decoded sizes plus 4,096 bytes. Output capacity equals the
declared decoded size. For zero-size outputs a harness can allocate a one-byte
backing buffer while passing capacity zero. These are conservative fixture
buffer sizes, not a guarantee that all native body paths accept those buffers.
The constructor, key-loader initialization and VM-backed body continuation must
execute normally; this tool supplies no replacement implementation for them.

The key-loader mapping is visible at `0x00C76CCF`: ECX is the archive object plus
`0x54`; the first two arguments come unchanged from the outer wrapper's
`[EBP+8]` and `[EBP+0xC]`, followed by the full raw-block vector's beginning and
length. `0x00C76D50` forwards the same four words at `0x00C76D62`. A real upstream
call at `0x00E3D2B5` supplies an empty readable name buffer at `0x011F4B90` and
length zero through `0x00C71C30`; it does not supply the footer timestamp.
The C71C30 path separately compares timestamps and selects the latest raw block.

The ABI addresses are specific to the researched 20260930 executable. They
must not be reused against another build. This generator is separate from the
[optional Frida decoder](../docs/native.md): it prepares fixtures and never
starts a client. Native integration requires its own exact executable profile,
normal initialization and independently observed results.

## Controlled malformed cases and reporting

All three negative entries use synthetic content and deterministic inline key
material. The Python replay requires their specific rejection stages:

- `negative/header-checksum`: altered clear header checksum.
- `negative/output-hash`: altered output XXH3 with the header checksum rebuilt;
  the short stored body remains intact.
- `negative/pkcs7-padding`: altered legacy cipher-5 ciphertext that breaks its
  required PKCS#7 padding.

For those cases, `codec` intentionally records the original valid header
metadata for bounded buffer allocation and identifies this in
`codec_metadata_note`. Do not interpret it as the corrupted header's contents.

A native harness should record each actual return value, output length/hash,
exception or timeout, and compare valid outputs with the expected hashes. It
should report native behavior of the malformed cases as observed, including any
unexpected acceptance, rather than assuming Python and native checks coincide.
No native observations are included in the frozen index.

Generated payloads, filenames, archive keys and private game data stay under the
Git-ignored `artifacts/` directory. Only this generator, its tests and these
instructions belong in source control.
