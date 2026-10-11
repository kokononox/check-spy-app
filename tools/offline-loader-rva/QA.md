# Validation — offline RVA 0.1

Tested source commit: 652fde517e9ac95324f4a9a1715e686d77a9ad67
Windows Actions run: https://github.com/kokononox/check-spy-app/actions/runs/38153385627
Status: PASS on Windows Server 2022, Windows PowerShell 5.1 and PowerShell 7.

- 25 pure parser/privacy/range/snapshot assertions.
- Owned fake saved session + non-executable header-only PE bytes: correct exception/thread-start/frame-return relative offsets; changed disk hash discards mapping; outside session rejected; private symbols/arguments/absolute addresses/paths not exported.
- WinForms GUI construction: PASS, not all interactive clicks or failure races.
- No user reports/hashes/game files uploaded or executed. No CDB invocation or network/game execution in extraction tests.
- Actual user's saved-session extraction and actual runtime mapped memory identity: NOT TESTED / NOT ESTABLISHED.
- Breakpoint origin, unwind accuracy, actual instruction execution and network send: NOT ESTABLISHED.
