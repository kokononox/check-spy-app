# Validation — 0.7 experimental

Tested source commit: 66ad66aa3985a6c0cc7e39dd784e9d3e777904c4
Windows Actions run: https://github.com/kokononox/check-spy-app/actions/runs/38151724066
Status: PASS (Windows Server 2022; Windows PowerShell 5.1 and PowerShell 7).

- 24 debugger core, 44 diagnostic/privacy, 33 startup parser/privacy/read-state assertions.
- GUI construction/layout only; not all interactive clicks/failure races.
- Owned fixture CDB dump/stop, running-process attach gate, initial breakpoint metadata, post-continue synthetic AV snapshot: PASS.
- NEW owned initial-AV native fixture: first observed stop was raised first-chance AV; loaded own harmless DLL; disk hash baseline matched; current-thread bounded stack and .exr Write classification captured; initial gate remained blocked; no continuation or handled marker before stop; own target survived debugger end. No network/game/credentials.

AV is deliberately raised by RaiseException with synthetic parameters, not a real invalid memory access. Only our C/C#/PowerShell sources and owned baselines were used. Fixture-only -g launch bypassed its standard initial launch breakpoint to reach the artificial AV; production observer/helper/UI did not gain a startup continue. Real game, unknown loader behavior, valid SSPI context, Schannel encryption, server receipt and definitive detach success remain NOT ESTABLISHED. Short identity/event check-to-command races and untested UI failures remain. No protections bypassed.
