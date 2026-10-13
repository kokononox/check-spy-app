# Targeted Request Capture 1.0 (experimental)

Portable Windows x64 prototype observing exported WinHTTP, OpenSSL write, and SSPI EncryptMessage APIs with Frida. It does not extract TLS secrets, discover hidden/static functions, guess RVAs, bypass anti-cheat, alter TLS validation or auto-elevate. Frida instrumentation itself can temporarily alter process code. Explicit risk/consent and process-selection confirmations precede attachment. It may crash protected targets or conflict with game rules; do not use where instrumentation is forbidden.

`START.cmd` launches the bundled Python runtime. All raw content remains in local PRIVATE-* files. Share only `Report-to-share.json`, which excludes full URLs, query strings, payloads and hardware values. API acceptance is not proof of server receipt. Stage labels are manual. Negative capture results do not prove absence of transmission. Game compatibility and real TLS interception are not established by the owned WinHTTP fixture.

Tests: `python tests/test_analyze.py`. Windows: build exact runtime with `python tests/build_runtime.py`, then `runtime/python.exe tests/test_windows_native.py`. The native test attaches ONLY to an owned synthetic client and checks optional POST data and split WinHttpWriteData against an owned loopback server. No user executable or report is involved. See README-fa.md for user instructions.
