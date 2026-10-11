# Validation boundaries

- Pure command generator and bounded log/HTTP1 parser: 22 synthetic checks pass on PowerShell 7.4.7 Linux.
- Five PowerShell scripts parse without syntax errors on that host.
- No user binaries, private logs, ETL, accounts or TLS keys are bundled or sent to CI.
- CDB commands and target attach are experimental. Core test success is not live CDB validation.
- Optional Windows ABI smoke test calls EncryptMessage with a deliberately invalid context in the kit's own fixture. It performs no network/TLS handshake and does not prove a successful encryption/send.
- If CDB is absent, the smoke test explicitly reports NOT RUN. No debugger is downloaded automatically.
- Real game, anti-cheat compatibility, actual Schannel-context identity, encryption result, socket send, HTTP2/3, compressed/protobuf body interpretation: NOT VALIDATED.
- Raw capture is sensitive even when private body-file output is disabled. Only Report-to-share.json is intended for sharing after review.
- Consent gates are operator attestations, not technical proof of an isolated environment. Never run against a real account/online anti-cheat session.
