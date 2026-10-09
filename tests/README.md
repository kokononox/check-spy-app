# Development test records

These are synthetic test harnesses from the development session, not captured user traffic and not a ready-to-run CI suite. Some paths and fixture conventions refer to the Linux `/data` development environment; adapt them before running in a different checkout. Windows GUI, trust-store and live PID APIs were not exercised end-to-end.

- diagnostics: PE32 fixture, real PE64 input in the private lab, malformed PE, marker names, allowlisted counts, no private sentinel in exported summary, target hash unchanged.
- proxy: request parsing, CONNECT byte identity/counts, private-destination block, unrelated-process rejection (injected QA resolver), shutdown, HTTP forwarding and credential stripping; real TLS tunnel with original origin certificate unchanged.
- startup: Starting/Ready/Failed/Closed round trip, atomic status file, path redaction, visible launch and STA structural checks.
- tls: exact host/scope, JSON field categories, opt-in exact identifier matching, bounded gzip/unknown binary handling, no values or URL paths in summary; real scoped interception and passthrough account connection against a synthetic origin with upstream validation active.

Use `app/Test-Syntax.ps1` on Windows for parser checks. Do not run TLS trust-store experiments in CI or production without deliberate opt-in and verified cleanup. The test sources contain obvious synthetic PRIVATE_* strings; they are not real credentials.
