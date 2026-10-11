# Validation boundaries — 0.5 read-only fault snapshot

Windows CI: https://github.com/kokononox/check-spy-app/actions/runs/38147541005
Tested source commit: 1e79ef1c9e2a1a8de97270681db4993ff97a44a1

- 24 core and 44 diagnostic/privacy synthetic assertions PASS in Windows PowerShell 5.1, PowerShell 7; also Linux PowerShell 7.4.7.
- GUI construction/default gates/bounds PASS; full real UI interactions NOT TESTED.
- Own CDB invalid-SSPI-context fixture, own running-fixture attach, explicit expected initial continuation, dump parsing, stop/own-target survival PASS. No real TLS handshake/network.
- Own native C fixture raises an artificial first-chance access-violation record with operation 8. It does not execute invalid memory. CDB pauses; helper reads .lastevent/.exr only, parser classifies record as Execute, and no g/gn/interrupt is sent by snapshot helper. Owned target remained paused before stop and survived debugger end. PASS.
- Snapshot request is once-only, strict own-CDB/helper console scope, process generation/hash rechecked. Unknown state refuses. Queueing is not proof of record completion/execution. Log framing and limited English text are evidence, not complete live-state proof; races remain.
- Complete AV record only: Parameter[0] is classified, all fault addresses/other parameter values remain PRIVATE. Safe report never includes raw pointer/path/URL/header/body.
- Stop helper is separate and may interrupt for detach; detach itself may let target handle a pending exception. No exception-continuation command is issued by snapshot helper. Exit/target survival do not prove every detach instruction succeeded.
- User isolation/private-capture checkboxes are attestations, not verified environment isolation. No game binary, raw user log, capture, credentials or key uploaded to CI. Only our source and fixtures.
- Real game/anti-cheat, actual cause of its AV, real Schannel context, live URL/body/send, second chance/unrecognized fault records, all failure races, other output languages/builds and Unicode paths are NOT VALIDATED.
