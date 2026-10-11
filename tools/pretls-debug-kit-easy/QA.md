# Validation boundaries — 0.2 easy experimental

Windows CI: https://github.com/kokononox/check-spy-app/actions/runs/38140791990
Tested code commit: 5c3ecd9f98c5106d4258dd32f0c68dc515d50194

- Core: 24 synthetic checks, PASS on Windows PowerShell 5.1 and PowerShell 7; also PASS on Linux PowerShell 7.4.7.
- GUI: construction, required controls, bounds, disabled initial capture controls PASS on both Windows shells. No actual interactive attach/UI click integration validated.
- CDB: required installed x64 CDB observed own deliberately-invalid-context EncryptMessage fixture. ABI/commands/dump/parser PASS. No TLS, credentials, or network.
- Stop: independent helper interrupted and detached own CDB in a console with exactly the debugger and helper; own held fixture survived. PASS. Test launches fixture under CDB; it does not exercise GUI attach to an already-running target.
- Stop helper refuses consoles with extra participants. No force-kill in user UI/helper; only OWN CI fixture cleanup uses process termination.
- Consent gates are attestations, not technical environment isolation verification.
- Real game, anti-cheat, attach failures, all stop failures, actual Schannel identity, encryption result, network send, Unicode CDB paths, HTTP2/3, compressed/protobuf body: NOT VALIDATED.
- No user binary/private log/ETL uploaded. Only our source and synthetic fixtures used in Actions.
- Raw log may include secrets even with body output disabled. Only Report-to-share.json is intended for sharing after review.
