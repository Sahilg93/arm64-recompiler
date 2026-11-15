# Run Windows executables on Apple Silicon

`run_windows.py` launches the original `.exe` with Wine. It preserves command
arguments, standard input and output, and exit status. This workflow uses Wine
and Rosetta on the tested Mac. The recompiler's native ARM64 conversion remains
available through `convert.py`.

From the extracted tool folder, run `python3 setup_wine.py` once on an Apple
Silicon Mac with Rosetta installed. Setup downloads and checks the tested Wine
archive, then installs it next to the launcher. The first launch creates a
local `wine-prefix` directory.

The launcher checks the local installation, PATH, and Wine Stable in
Applications. Use `--wine` or `WINDOWS_WINE` to select a different installation.
See [WineHQ's macOS packages](https://github.com/Gcenx/macOS_Wine_builds).

```sh
printf '{"answer":42}\n' | python3 run_windows.py /path/to/jq.exe .answer
python3 run_windows.py /path/to/rg.exe -n needle 'Z:\path\to\file.txt'
python3 run_windows.py /path/to/plink.exe -V
```

Wine maps macOS paths through its Windows drive mappings. The usual `Z:`
mapping provides access to macOS paths. Pass Windows-style file arguments
where an application expects them. An optional `--prefix` before the executable
selects a separate Wine configuration directory.

## Verified on this Mac

| Windows release | Tested behavior |
| --- | --- |
| jq 1.8.2 | Version and JSON field extraction from stdin |
| ripgrep 15.1.0 | Version, matched line with line number, and no-match exit status |
| Plink 0.83 | Version, raw localhost TCP, and SSH command execution with pinned host key, password authentication, separate stdout and stderr, and exit status 23 |

Tests used Wine 11.0. The SSH endpoint was a local test server. GUI applications
and other executables have not been validated. Wine compatibility depends on the
application and its Windows dependencies. Only run files you trust.
