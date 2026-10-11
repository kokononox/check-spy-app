# Validation boundaries — 0.4 startup-gated experimental

Windows CI: https://github.com/kokononox/check-spy-app/actions/runs/38144231860
Tested code commit: 2793584549b310c93d9d73a5b223e46c0dbac15f

- Core: 24 synthetic command/parser/privacy checks PASS in Windows PowerShell 5.1 and PowerShell 7, also Linux PowerShell 7.4.7.
- Diagnostics: 35 synthetic checks PASS on both Windows shells and Linux. Cover expected initial break, unknown/fault/second-chance/later-event rejection, no unconditional startup g, one continuation marker, old fault-then-g-then-break replay, payload exclusion and privacy/end evidence.
- GUI: construction/bounds/required controls/default disabled capture and initial-continue controls PASS. Full interactive clicks are NOT TESTED.
- Real CDB, own launched invalid-context fixture: initial snapshot recognized; no automatic startup g; explicit test helper request queued initial continue; exactly one API handler entry and own dummy HTTP candidate parsed. PASS. -2 separates fixture console so strict helper scope is not relaxed.
- Real CDB, attach to own already-running local-file-rendezvous fixture: expected initial break required; explicit test request continued; invalid-context buffer captured; stop ended CDB and own target generation survived. PASS. This exercises -p attach, but not actual UI clicks/game.
- Owned console stop integration: PASS. Console must contain exactly CDB and helper. No force-kill in user UI/helpers; tests may terminate OWN fixtures/helpers for cleanup.
- Private old user log replay only LOCAL: fault before initialization, prompt g after initialization, later 80000003 break all detected; zero API entries. No user raw log/ETL/binary uploaded to GitHub/Actions.
- Raw exception snapshots contain sensitive addresses/parameters; private log stays local. Safe report contains only enumerated states/counts, never paths/addresses/URL/header/body.
- Gate recognizes only bounded English CDB output and expected ntdll break symbols. Snapshot match does not establish origin of breakpoint; PID/console/log races remain possible. Unknown/error evidence fails closed. User attestations do not prove isolation.
- A queued g or marker is not proof of execution/running state; later API entry is separate evidence. Stop request, debugger exit and target survival do not prove every detach instruction succeeded.
- Real game, anti-cheat, accounts, all failure races, other CDB languages/builds, Unicode CDB paths, actual Schannel/TLS handshake, successful encryption/network send, HTTP2/3/chunked/compressed/protobuf: NOT VALIDATED.
