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
