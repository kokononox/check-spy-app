# Validation — 0.8.3 independent code reader

Tested source commit: 992fb37802a9323c2c6a682f1e8d5ab6c80c36ea
Windows Actions run: https://github.com/kokononox/check-spy-app/actions/runs/38176682970
Status: PASS, Windows Server 2022.

- 24 debugger, 44 diagnostic/privacy, 33 startup-state, 21 callback-slot and 26 code-window/eligibility/privacy assertions.
- Fresh child UI tick: BOTH initial gates schedule mock code; expected ntdll gate schedules no callback; no continuation requested; parser-failure overdue stop path covered. Expected normal gate may permit explicit user continuation by original policy, but no continuation is requested by these tests/helpers.
- Native CDB normal running-process attach: own DLL loaded; expected ntdll initial break; NO callback helper/receipt; independent 48-byte comparison and safe export successful; no initial continue; own target survives debugger end.
- Native custom owned DLL breakpoint: callback and independent code succeed; 48 bytes equal file. Separate own padding-byte mutation run correctly detects entry offset20. Mutation exists only in OWN C fixture, never production reader or user game.
- Wrong loader hash refuses before queue. Prior owned fault/attach/stop tests passed.
- Failed intermediate tests revealed stale local override after .frame /c 0. Reselecting the same recorded OS-thread reset debugger context; exact TID/RIP guards retained. No widening/resume workaround.

Only tool sources/OWN tests used in CI; no user hashes/config/code/game files uploaded or executed. Real game and unreliable runtime unwind NOT tested. 48-byte match is not full mapped-image identity; difference cause and actual callback invocation remain unknown. Relocations not normalized. No network content/full URL/TLS/send/server receipt established. Mock UI tests are not all live clicks/failure races; stop/detach markers are not definitive detach proof.
