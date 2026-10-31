# Protected GRF format implemented by grfkit

This documents the protected payload used by file-table flag `0x80` in live
kRO GRF v3 archives. The containing GRF table, outer alignment, and older DES
flags are handled separately. Give `decode_entry` the exact compressed payload,
without its outer alignment bytes. Filenames must be the original bytes stored
in the file table, including backslashes and the original text encoding.

The implementation follows upstream `src/grf_protected.rs` and
`src/grf_ciphers.rs` at the revision identified in [NOTICE](../NOTICE). Its frozen
tests reproduce the independent Python encoder in upstream
`tests/fixtures/generate.py`; these vectors use synthetic data, with no
copyrighted game assets or executable dependencies. The optional upstream
checkout lives outside this repository; see [optional references](../README.md#optional-references).

## Entry layout

All numeric fields are little endian. Every payload begins with a 104-byte
header. Bytes 0 through 7 are clear; bytes 8 through 103 are encrypted.

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 1 | Format version, 1 |
| 1 | 1 | Header cipher variant |
| 2 | 2 | Reserved, emitted as zero |
| 4 | 4 | XXH32 of the decrypted bytes 8 through 103, seed zero |
| 8 | 2 | Body cipher ID: 1, 5, 7, 128, or 133 |
| 10 | 1 | Compression: 0 stored, 1 zlib, 2 raw LZ4 block |
| 11 | 1 | Parameter flags: only bit zero is supported |
| 12 | 4 | Physical body size, including cipher padding |
| 16 | 4 | Compressed plaintext size, excluding cipher padding |
| 20 | 4 | Final uncompressed size, limited to 256 MiB |
| 24 | 16 | XXH3-128 of final output, native x86 little-endian integer order |
| 40 | 4 | Archive key ID, or zero for inline material |
| 44 | 60 | Inline parameter material |
| 104 | variable | Encoded body |

Header variants 1, 2, and 15 use AES-128-CBC with key
`56fd7e712f6d36f55ca599e67b18107a`. Their IVs are respectively the constant
`4ce8a1ae45b321607e4f26a4bb140c96`, the filename XXH3-128, and XXH3-128 of
the four clear checksum bytes. Variant `0x71` uses ThreeWay with 12-byte CFB
segments, key `ad61aedabf203e1dfe1db72b` and IV `a095dfcfd04b74db027ede09`.

The selected 60-byte inline or archive material is XORed cyclically with the
16-byte output hash if parameter flag bit zero is set. Four zero bytes extend
the result to 64 bytes. These derived bytes are called `p` below. All offsets
below are half-open byte slices. The first 128 compressed bytes are unchanged;
body processing starts after them and only occurs when compressed size is
greater than 128.

## Body transforms

IDEA masks consist of two CBC-encrypted 8-byte blocks of the indicated 16-byte
input, starting from the indicated 8-byte IV. The resulting 16-byte mask repeats
through the relevant tail. CHAM uses 80 rounds and big-endian 32-bit words.
RC6 uses 20 rounds and little-endian 32-bit words. ThreeWay uses 11 rounds.

| Cipher | Decoder operations on the tail |
| --- | --- |
| 1 | CHAM-CBC-decrypt up to 1024 complete bytes, then undo the chained four-byte rotation and XOR across the entire tail |
| 5 | AES-CBC-decrypt a PKCS#7-padded prefix of up to 1024 compressed bytes using key `p[0:16]`, IV `p[16:32]`; XOR the remaining bytes with IDEA mask keyed by filename hash, input output hash, IV `p[48:56]` |
| 7 | Same prefix and suffix structure as 5, with AES key `p[28:44]`, IV `p[44:60]`, and IDEA mask keyed by output hash, input filename hash, IV `p[52:60]` |
| 128 | AES-CBC-decrypt complete blocks of the entire tail when tail length is below 3072; otherwise decrypt only tail bytes 2048 through 3071; then XOR the whole tail with IDEA mask keyed by output hash, input filename hash, IV `p[49:57]`. AES key `p[44:60]`, IV `p[28:44]` |
| 133 | RC6-CFB-decrypt up to 1024 complete tail bytes using key `p[24:40]`, IV `p[40:56]`; then XOR the whole tail with IDEA mask keyed by filename hash, input output hash, IV `p[49:57]` |

Cipher 1 uses filename XXH3-128 seeded with final output size, called `m`.
The CHAM key is XXH3-128 of `p[0:60]`, seeded with the native little-endian
high 64 bits of `m`; its IV is the output hash. After CBC decoding, each
complete block `x` becomes `rotate_bytes_right(x, 4) XOR
rotate_bytes_right(m, 4) XOR previous`, where the previous value initially is
the output hash and subsequently is the previous `x`. Partial final bytes are
XORed with the corresponding initial bytes of `m` and `previous`.

Encoding reverses those operations. Cipher 5/7 prefix padding always adds
between 1 and 16 bytes, including a full padding block for an aligned prefix.
The complete expected padding size and each PKCS#7 byte are checked on decode.
The encoder emits no redundant physical padding for the other ciphers.

## Archive key block

An absent key block is represented by empty bytes. Otherwise its 20-byte clear
header is `01 01 00 00`, an eight-byte timestamp/revision field, a four-byte
ciphertext size, and XXH32 of the decrypted records. Each 64-byte record holds
a four-byte ID followed by 60 material bytes. IDs must be unique and in
`1..65535`. The reader tries two CHAM-CBC derivations in order: SHA-256 of ASCII
`uf8E8qAwHthrLxiS`, then SHA-256 of ASCII `xifEFhJEjducBA7U`. Each digest's first
16 bytes supply the key and its last 16 bytes supply the IV. Both use the same
clear marker. Each attempt decrypts the original stored body and must match the
stored XXH32 before any records are accepted. No default-key substitution is
performed when these checks fail.

The alternate derivation was observed in the exact-profile Windows native key
loader and checked against the patch-7436 September archive. The first derivation
produces checksum `0xd8b017ec` for that block; the second produces its stored
`0xa5bbcbbb` and records ordered 4,1,2,3. The
[native key-block probe](native.md#archive-key-loader-validation) owns the input
identities, controls and reproduction procedure. This is actual body decoding,
separate from recognition of default-key checksums in `01 00 00 00` blocks;
that marker remains unsupported by this Python reader.

`encode_keys` emits records in ascending ID order and a deterministic revision
of **1** by default, using the first derivation. Native archive wrappers skip
zero revisions before calling
their key loader. An explicit `encode_keys(keys, timestamp=value)` accepts
integer revisions in `1..INT64_MAX`; zero, negative and larger values are
rejected for newly encoded blocks. Existing zero-revision blocks remain
readable, and passing an existing `raw_keys` block to `Writer` preserves its
bytes, including its derivation and revision.

The client can choose the newest signed-positive revision across mounted GRFs
and apply that same key block to every archive context. The default 1 is
deliberately low priority, rather than the current UTC time: a new custom key
map must not silently supersede an official newer key map. Coexistence of
arbitrary custom footer-key IDs requires deliberate key-map and revision
management; preserving a source block avoids changing its declared priority.
This revision rule does not establish native body-decoder acceptance, and no
unused footer is automatically added to archives containing only inline keys.

`encode_entry` accepts all supported variants and generates random 60-byte
inline material when none is supplied. Set `key_id` and pass the archive map
to use a shared archive key. A renamed file must be encoded again using its
new raw filename, because the header IV and body transforms can depend on it.

## Validation and limitations

Decoding checks header and key-block checksums, exact physical payload length,
declared sizes, supported algorithms and flags, archive-key lookup, legacy
padding, decompression completion and final output hash. Zlib decoding is
bounded to the declared output plus one sentinel byte; LZ4 decoding allocates
at most its declared size. Stored output must match its declared size exactly.

XXH32 and XXH3 are integrity checks, not cryptographic authentication. Unknown
variants fail explicitly rather than returning undecoded bytes. No game client
is required by the codec or its tests.

From the repository root, the following streams through all protected entries,
checks every output, and writes a per-entry SHA-256 manifest plus summary. It
also computes the entire input archive SHA-256. Both output paths must be new.

```sh
python validation/protected_verify.py \
  /mnt/c/kRO/data.grf artifacts/protected-verified.jsonl \
  artifacts/protected-verified-summary.json
```
