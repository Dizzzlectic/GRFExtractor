# Independent GRFEditor reader

This console harness uses GRFEditor's `GrfHolder`, file-table parser and decoder
to emit JSONL containing displayed path, flags, decoded length and SHA-256. An
optional expected-directory argument compares decoded content. It is an optional
independent check of Python writer output, not a runtime dependency.

## Prepare a disposable source copy

Run from the GRFExtractor root. The upstream checkout defaults to `../GRFEditor`;
set `GRFEDITOR_ROOT` to override it. If the destination does not exist:

```sh
git clone https://github.com/Tokeiburu/GRFEditor.git ../GRFEditor
```

Preserve an existing working checkout. Fetch the pinned protected-GRF PR and
build a disposable source archive without switching or modifying that checkout:

```sh
grf_editor="${GRFEDITOR_ROOT:-../GRFEditor}"
git -C "$grf_editor" fetch https://github.com/Tokeiburu/GRFEditor.git pull/20/head:refs/remotes/pr/20
mkdir -p scratch/grfeditor
git -C "$grf_editor" archive 7582a851dcff77cd741cd7176470cedc3cc72fac | tar -xf - -C scratch/grfeditor
dotnet build interop/GrfInterop.csproj "-p:SolutionDir=$PWD/scratch/grfeditor/" --nologo -v:q
```

Use a new/empty `scratch/grfeditor` directory. GRFEditor's build targets refresh
DLLs in its `Libraries` directory, so only the disposable source copy is built.
The project defaults `GrfEditorSource` to that directory; an alternate absolute
path must end in `/` and be supplied as both `-p:GrfEditorSource=...` and
`-p:SolutionDir=...`.

The Linux .NET SDK builds this harness for Windows .NET Framework 4.8. GRFEditor's
compression initialization loads Windows DLLs even when managed zlib is selected;
run the executable on Windows. From WSL, convert paths using `wslpath -w`, then
use PowerShell with the resulting executable/archive paths:

```powershell
& 'PATH_TO_GrfInterop.exe' 'C:\path\archive.grf'
if ($LASTEXITCODE) { exit $LASTEXITCODE }
```

The executable also accepts `--vectors PATH_TO_FIXTURE_BUNDLE`, where the pinned
bundle is `scratch/grfeditor/Tests/fixtures/protected-grf.bin`. It checks accepted
and malformed vectors using the unmodified C# decoder. The upstream harness can
be built independently:

```sh
dotnet build scratch/grfeditor/Tests/ProtectedGrfTests.csproj "-p:SolutionDir=$PWD/scratch/grfeditor/" --nologo -v:q
```

Run its resulting `Tests/bin/Debug/net48/ProtectedGrfTests.exe` on Windows.

## Check Python writer output

After installing this Python package, generate synthetic protected entries and
separate expected decoded files:

```sh
python interop/make_matrix.py scratch/python-matrix
```

The matrix covers 360 combinations of five body ciphers, four header types,
three compression modes, two parameter flags and three key sources (inline,
footer ID 7, footer ID 42), plus 65 empty/boundary cases. Boundary lengths are
0, 1, 127, 128, 129, 143, 144, 1151, 1152, 1153, 3199, 3200 and 3201 bytes.
Protected names include CP949 characters. The generated archive is about 596 KiB.

Run `GrfInterop.exe MATRIX_GRF EXPECTED_DIRECTORY` on Windows, converting WSL
paths as needed. It must report all 425 entries read/hashed and matched. Remove
disposable generated files after retaining any needed summary outside source.

For a written archive, redirect harness stdout to JSONL and compare it with a
Python verification manifest:

```sh
python validation/compare_csharp.py artifacts/verified.jsonl artifacts/csharp.jsonl --summary artifacts/csharp-checked.json
```

The comparator rejects missing/extra members, duplicate logical names and changed
lengths/hashes. GRFEditor uses case-insensitive dictionary keys and normalized
separators, so it can collapse distinct raw table records. The comparator refuses
to claim raw-record equivalence for those collisions; use
`validation/verify_repack.py` to check raw names and order separately.

Do not generate multi-gigabyte repacks merely to repeat a bounded codec check.
Broaden to complete archives when the format change or observed failures require
it. C# decoding success does not establish native-client decoding or gameplay.
