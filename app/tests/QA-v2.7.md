# QA v2.7

Environment: Linux, PowerShell 7 parser/runtime and tshark. This does not replace Windows PowerShell 5.1 / WinForms / Explorer / live Pktmon validation on Windows 11.

Passed:
- Parsing of all bundled PowerShell scripts.
- Existing analyzer regression: IPv4/IPv6, TCP/UDP, tuple/time exclusion, optional identifiers, missing-field degradation, X509 warning quarantine, fatal nonzero exit, temporary-output cleanup.
- Synthetic bidirectional fixture: outbound 4, inbound 1, readable outgoing 2; TCP payload outbound 200 / inbound 50; UDP outbound 22; inbound metadata does not become outgoing evidence; arbitrary ALPN is excluded.
- Synthetic local-log audit: appended/rewritten/unchanged files, time-window filtering, historical/undated exclusions, fixed semantic categories, no raw values or paths exported, safe field-name/header and resource redaction.
- Existing private real capture regression: outbound correlated frames remain 495; inbound 503; eight endpoint groups; endpoint frame sums equal global directional counts. Observed transport payload totals: outbound 34906, inbound 217946 bytes. Readable outgoing evidence frames: 0. No TLS decryption asserted. Strict raw Wi-Fi normalization uses a derived copy, not the original.

Real captures, real device logs, report JSON and private test output are not included in this public source/package. These counts describe one prior capture, not a new recording or proof of information types sent. Byte totals include possible retransmission and protocol overhead.

Run tests/Test-Analyzer.ps1, tests/Test-Bidirectional.ps1 and tests/Test-Local-Audit.ps1 for synthetic tests. Some historical harnesses remain environment-specific; no production CI claim is made.
