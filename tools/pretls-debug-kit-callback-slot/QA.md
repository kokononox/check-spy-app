# Validation — 0.8 experimental

Tested source commit: 85befdfb57306e65185eb1443f4c0271d9659b4e
Windows Actions run: https://github.com/kokononox/check-spy-app/actions/runs/38157284701
Status: PASS (Windows Server 2022, Windows PowerShell 5.1 and PowerShell 7 core/GUI construction).

- 24 debugger-core, 44 diagnostic/privacy, 33 startup-state/privacy and 21 callback-slot numeric guard/parser/privacy assertions.
- Previous owned CDB dump/stop, attach gate, initial metadata, artificial initial AV and fault record fixtures: PASS.
- NEW owned asm DLL callback: custom first-chance CC, correct x64 unwind metadata; recorded frame-1 Child-SP equals debugger local override RSP; TID/RIP/RSP guards passed; exactly one qword maps to expected own callback RVA; restore marker observed; safe export omits pointers/paths; wrong loader hash refused BEFORE queue; no initial continuation or handled marker before stop; own target survives debugger end.
- Fixture-only -g skips standard launch break to reach its custom break; production observer/helper/UI gained no startup continue.

Only owned synthetic DLL/C/asm sources/config/hashes used in CI. No user files, hashes, config or raw captures uploaded/executed. No real game/network test. Real obfuscated/unreliable unwind case, all GUI clicks/failure races, target mapped code identity, actual callback invocation, breakpoint origin, valid TLS/network send and definitive detach success: NOT ESTABLISHED. Local context restore command/marker is not general proof of recovery in every failure. Short identity/snapshot check-to-command races remain. No protection bypasses.
