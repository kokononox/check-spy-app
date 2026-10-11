# Validation and scope

- Core: 24 synthetic assertions covering direct/encoded URL hints, fixed API hints, aggregation, bounds and non-export of dummy tokens, paths, headers and body values.
- Parser: all 4 PowerShell scripts parsed with PowerShell 7.4.7 on Linux.
- Not validated: Windows PowerShell 5.1 runtime, Windows GUI, live ETW, the user’s original ETL/private JSONL, native EventRecord.FormatDescription().
- The original trace is not included in this package. No actual request payload or full HTTPS URL was recovered by these tests.
- Input files are read locally. Outputs contain aggregated structure and fixed-vocabulary hints, not raw event values.
- No networking, new trace, certificates, proxy changes, TLS bypass, process injection, or target execution.
- Unit tests use dummy strings only. They do not establish compatibility with every Windows provider event format.

Run tests manually on Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-ETW-Field-Core.ps1
```
