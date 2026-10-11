# Validation — 0.8.1 UI wiring fix

Tested code commit: 4f5a0375e4c0e0bfc0053c4f3480f0469e99ad0f
Windows Actions run: https://github.com/kokononox/check-spy-app/actions/runs/38158044970
Status: PASS on Windows Server 2022.

- Prior debugger/diagnostics/startup/callback parser assertions and owned CDB/asm fixtures passed.
- NEW fresh child process in both Windows PowerShell 5.1 and PowerShell 7: actual UI tick body imports its own parser, schedules mock callback and overdue mock stop; deliberately throwing context parser still schedules overdue mock stop; continuation gate remains blocked. No target/CDB/helpers invoked by UI tick mocks.
- GUI construction and tick mocks do NOT cover all real UI clicks, live timing, parser errors or hangs. Owned CDB helper fixtures are separate from UI scheduling tests. No real game test.
- The 0.8 missing UI parser import was not caught by the earlier layout/direct-helper tests; this regression test now covers that independent launch path.
- Unchanged callback helper still reads one guarded qword and exports candidate module/RVA only. Actual call target, runtime unwind, breakpoint origin and network send remain NOT ESTABLISHED.
- Offline extractor bundled without source changes, previously tested: https://github.com/kokononox/check-spy-app/actions/runs/38153385627
- No user data/config/hash/game files sent to CI. No protections bypassed.
