# Validation — 0.6 experimental

Tested source commit: 3ece526981db677937c1a6516f6218c76516a711
Windows Actions run: https://github.com/kokononox/check-spy-app/actions/runs/38149518964
Status: PASS (Windows Server 2022, Windows PowerShell 5.1 and PowerShell 7).

- 24 debugger-core synthetic assertions; 44 diagnostic/privacy assertions; 23 startup metadata/parser/privacy assertions.
- GUI construction/layout checks; not all user clicks or failure races.
- Own invalid-context SSPI fixture, bounded dump and safe export; NO valid security context/TLS/network.
- Own running-process attach: no startup auto-go, explicit synthetic continuation, own target survives debugger end.
- Own raised AV fixture: read-only exception metadata, Execute classification, no continuation before stop. Artificial RaiseException parameters, not real invalid memory access.
- NEW own harmless DLL/EXE: disk fingerprints match own temporary baseline; event-thread query succeeds, start address matches verified ntdll remote-breakin export; current thread matches last event; bounded stack has rows; no initial continue; safe report excludes private metadata; own target survives debugger end.

A first Windows run caught unsupported unnumbered kv rows; parser was corrected and this run passed. No game files or user reports were uploaded or executed. Actual unknown-loader initial-break case has NOT been runtime-tested by us. Successful fixture tests do not establish breakpoint origin, game compatibility, actual encryption/network send, or definitive detach completion. No protections were bypassed. Console identities and event snapshots are revalidated, but short check-to-command races remain.
