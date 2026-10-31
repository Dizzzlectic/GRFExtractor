# Native decoder

See the [README](../README.md) for ordinary extraction and
[extraction notes](extraction.md) for manifests and recovery.

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

## Archive-key loader validation

Use [native_keyblock_probe.py](../validation/native_keyblock_probe.py) and its
[JavaScript probe](../validation/native_keyblock_probe.js) with the Windows
runtime and exact executable profile described above. They call the archive-key
loader in an owned scratch process held at its original entry point. They do not
modify the archive or establish gameplay compatibility.

The probe runs the bridge's cipher initializers, then constructor VA `0x0078ac80`
and loader VA `0x0078d510`, at image base `0x00400000`, with a fresh context and
empty outer-name span. It reads the loader result and published record count.

`--trace-derivations` observes the loader on a separate thread. A hardware
watchpoint follows the final byte of its body-sized allocation. It reads the
digest at `EBP-0x49c`, CHAM schedule at `EBP-0x40c` and candidate seed at
`EBP-0x42c`. A digest is retained only when its key expansion matches the native
schedule; a seed is retained only when its SHA-256 matches the digest. Raw stack
frames and key records are not saved. The limits are eight watchpoint hits per
call, 15 seconds per call and a 60-second process watchdog. Successful cleanup
requires termination of the owned process.

The patch-7436 September archive uses the alternate derivation described in
[Protected format](protected-format.md#archive-key-block). Its key block is 276
bytes at file offset 4925701332, SHA-256
`59d6b14af3c44727326f1b41336f59f6a16417f585b9b99a70659a383d54b40d`.
The source `kRO-20260930/data.grf` is 4925701608 bytes, SHA-256
`f9ad4407c4f3d007b39305743f139611995ee46d77a4d75bbead55a30906c668`.
The loader accepts this block with four records. Flipping bit zero of its first
body byte or checksum byte makes it reject the block with no records.

### Reproduce

Copy the selected key block into scratch. With the portable reader, its bytes
are available as `Archive(path).raw_keys`; close the archive after reading.
Without decoding, read the little-endian u64 table offset at header byte 30
and add 46. At that position read the u32 key-block size and compressed-table
size. The key block follows the 12-byte table preamble and compressed table.
Check its identity above.

Using the Windows environment and variables described earlier:

```powershell
& "$research\python32\python.exe" "$research\tools\validation\native_keyblock_probe.py" `
  --client "$research\client\Ragexe.exe" `
  --agent "$research\tools\unlicense-agent.js" `
  --key-block "$research\real-keyblock.bin" `
  --trace-derivations --controls --output "$research\keyblock-probe.json"
```

Expect acceptance with four records after the alternate derivation, rejection of
both damage controls and `process_terminated: true`. The checked-in legacy
`tests/fixtures/protected-footer.bin` and alternate `ALTERNATE_FOOTER` in
`tests/grfkit/test_grfkit_protected.py` provide synthetic controls: each original
should yield one record and its two damaged variants should be rejected.
A different executable requires fresh address and calling-convention checks.
Ordinary archive operations do not require this probe or a running client.
