# Real Windows TLS proxy integration — owned fixtures only

This directory validates the proxy addon shipped in TLS-Diagnostics-All-in-One 1.2.
The workflow does not execute any user's game or use any user logs, reports, hashes,
settings, account data, binaries, certificates, or session keys.

## Coverage

- Real Windows IPv4 loopback TCP ownership/path checks (no attribution mock).
- Official mitmdump 12.2.3 archive and EXE checked against expected vendor hashes.
- Valid HTTPS proxy handshake and a JSON request received by an owned origin.
- An intentionally untrusted proxy CA and diagnostic indicator capture.
- A deliberate disconnect during the handshake, without any HTTP request.
- Rejection of a mismatched executable path.
- Non-scoped HTTPS passed through as an encrypted tunnel to the owned origin.
- Explicit private capture of ONLY owned synthetic URL/body, with header values excluded.
- Rejection of an untrusted origin CA while upstream certificate validation stays enabled.
- Comparison of CurrentUser Root store snapshots before/after; no OS CA imports.

Only one fixture-specific source substitution is made in a temporary copy:
`HOST = 'telemetry-in.battle.net'` becomes `HOST = 'localhost'`.
The production addon remains unchanged. The owned origin binds only loopback port 443.
Client and proxy trust are supplied through per-process CA files, not Windows Root.
This therefore does NOT test the GUI's CA-store installation/cleanup path or prove
compatibility with any game, its TLS backend, its proxy policy, or its trust policy.

All temporary certificates, private files and proxy logs stay in a disposable fixture
folder and are not uploaded as artifacts. Only a sanitized boolean/count/code report
is uploaded. Certificate keys are freshly generated owned fixtures, never user keys.

See `.github/workflows/tls-proxy-windows-integration.yml` for the CI entry point.
The workflow uses a read-only repository token and no persistent checkout credentials.
It downloads dependencies from their public vendors; these are setup downloads,
not captured or analyzed user traffic.
