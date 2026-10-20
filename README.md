# GRFExtractor

Extract, inspect, verify and repack Ragnarok Online GRF v2/v3 archives without
running the game. The portable codec supports ordinary zlib/stored entries,
legacy DES and supported protected kRO entries. Newly protected output can be
encoded after editing or renaming files.

## Install and use

Requires Python 3.11 or later. From this repository:

```sh
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .
grf inspect /path/to/data.grf
grf list /path/to/data.grf --match '*clientinfo*'
grf extract /path/to/data.grf extracted
grf verify /path/to/data.grf --match 'data/clientinfo.xml'
grf pack extracted edited.grf --protect
grf repack /path/to/data.grf plain.grf --mode plain
```

Canonical `grf extract` uses portable decoding. The compatibility `grf-extract`
interface also defaults to portable decoding without native inputs; its
`--portable` flag remains supported.
`grf` is the archive command (`grfkit.cli:main`); `python -m grfkit` is equivalent.
The existing `grf-extract --archive ARCHIVE --output OUTPUT` and
`python -m grf_extractor` interfaces retain resumable and optional native use.
Use `grf extract ARCHIVE OUTPUT --resumable` to checkpoint a new extraction,
then add `--resume` to continue it. `grf-extract` checkpoints by default. Unknown
protected formats and damaged entries fail explicitly.

Extraction keeps original filename bytes in `.grf-manifest.jsonl`, alongside
portable filesystem paths. Keep this file when editing and packing. With
resumability enabled, a separate versioned checkpoint binds resume to the archive, decoder and recorded output
hashes. See [extraction and recovery](docs/extraction.md) for selection, manifests,
collision handling, checkpoint compatibility and the exact opt-in WAV repair.

## Guides and source

- [Archive format](docs/format.md): container, legacy entries and codec limits.
- [Protected format](docs/protected-format.md): header/body transforms and encoding API.
- [Design](docs/design.md): ownership, publication and validation boundaries.
- [Native decoder](docs/native.md): optional exact-profile Windows/Frida decoding.
- [C# interoperability](interop/README.md): disposable independent reader checks.
- [Native fixture oracle](validation/NATIVE-GRF-ORACLE.md): bounded frozen inputs;
  preparing fixtures does not establish native decoder acceptance.

`src/grfkit/` owns the parser, portable codecs, writer and archive CLI.
`src/grf_extractor/` owns resumable extraction and the optional native bridge.
`tests/` retains the independent synthetic fixture bundle and extraction/native
regressions; `tests/grfkit/` retains the separate parser, encoder and writer
regressions. No game archives or executables are included.

## Check

Install the development dependencies with `python -m pip install -e '.[dev]'`,
then run the portable and bridge regressions:

```sh
python -m pytest -q tests validation/test_native_grf_oracle.py
node --test tests/test_native_decoder.cjs
```

The native bridge tests do not require launching a game client. Native execution
requires the separate prerequisites and exact profile in the native guide.
For routine resource changes, inspect the header/table and verify affected
entries. Changed archive size, hash or table order alone does not justify a
full-archive scan. Use fixture suites for codec/writer changes; broaden checks
for unsupported variants, widespread integrity failures or shared format changes.

## Optional references

The portable package needs neither Rust nor GRFEditor. Differential DES and
protected-fixture tests optionally use a sibling upstream checkout. Set
`GRF_REFERENCE_ROOT` to override `../roBrowserLegacy-RemoteClient-Rust`.
To create the pinned checkout when the destination does not exist:

```sh
git clone https://github.com/Flux159/roBrowserLegacy-RemoteClient-Rust.git ../roBrowserLegacy-RemoteClient-Rust
git -C ../roBrowserLegacy-RemoteClient-Rust checkout --detach a210fee29fef73eacf8a52ee3a4e79d59a5cf5cf
```

Preserve any existing working checkout. Optional reference checks skip when
files are absent; this project's frozen synthetic vectors still run. The
independent C# harness similarly uses `../GRFEditor` or `GRFEDITOR_ROOT`.
Generated archives and private fixtures belong in ignored `artifacts/`; disposable
reference source copies belong in `scratch/`.

GPL-3.0-or-later; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
