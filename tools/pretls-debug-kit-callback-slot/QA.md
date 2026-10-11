# Validation — 0.8.2 bounded code windows

Tested source commit: 792ccf1be440a70a93cb8d635d0208a2d8196908
Windows Actions run: https://github.com/kokononox/check-spy-app/actions/runs/38159240231
Status: PASS, Windows Server 2022.

- 24 debugger, 44 diagnostic/privacy, 33 startup-state, 21 callback-slot and 17 code-window/PE/privacy synthetic assertions.
- Fresh independent GUI tick tests and prior owned CDB/fault/attach fixtures: PASS.
- Owned ASM DLL unmodified: 32 entry +16 exception bytes compare equal to file-backed executable PE regions.
- Separate owned ASM DLL run: C fixture deliberately changes ONE unused padding byte at entry offset20 in its OWN memory; parser finds exact one-byte mismatch. No user-game memory is modified or uploaded. Production reader does not contain this mutation capability.
- Both real CDB fixture runs: guarded callback candidate, complete windows, safe export without raw code/pointers, wrong loader hash refused, no initial continuation, own target alive after debugger end.
- First CI run exposed a missing parser import in the integration TEST script; test dependency corrected before this passing run.

Limits: game and unreliable obfuscated unwind NOT tested. ASLR relocation not normalized; difference cause unknown. Small window match is not mapped-image identity. cc offsets are byte matches, not proved instruction boundaries. No network/TLS/content/send/server receipt established. GUI tests use mocks, not all live clicks/failure races. Stop/detach markers are not definitive general detach proof.
