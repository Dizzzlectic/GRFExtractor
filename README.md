# GRFExtractor

Extract Ragnarok Online GRF v2/v3 archives, including older DES entries and
supported protected kRO entries. Portable extraction needs no game executable.
Archives are read only; this tool does not repack them.

## Use

Requires Python 3.11 or later. From this repository:

```sh
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .
grf-extract --portable --archive /path/to/data.grf --output extracted
```

Add `--resume` to continue an interrupted extraction, or repeat `--entry 'data\file.txt'`
to select files. Output includes a sibling JSON manifest with SHA-256 hashes and
failures. Unknown protected formats and damaged entries fail explicitly.
`python -m grf_extractor` is equivalent to `grf-extract`.

## Source

- `src/grf_extractor/`: archive parsing, CLI and extraction output handling.
- `src/grf_extractor/codecs/`: portable header, key-block and body decoding.
- `src/grf_extractor/native/`: optional Windows/Frida decoder and client profile.
- `tests/`: extraction regressions, synthetic decoder fixtures and native bridge checks.
- [Format and native-mode notes](docs/format.md).

## Check

After installing the package (use `pip install -e .` when editing):

```sh
python -m unittest discover -s tests
node --test tests/test_native_decoder.cjs
```

GPL-3.0-or-later. No game archives or executables are included.
