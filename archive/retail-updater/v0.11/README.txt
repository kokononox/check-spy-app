WoW Retail EU Index Completion v0.11 — NOT AN INSTALLER

Close WoW and Battle.net. Extract outside the game folder. Run START.cmd.
Existing Python 3.9+ 64-bit with tkinter/sqlite. No pip or Administrator.
Select ORIGINAL v0.9 Retail-Archive-Batch-to-share.json inside CDN-Batch-* in
previous staging, NOT the chat-downloaded copy. Then select installed .build.info.
Keep the entire previous staging/cache. At least 2 GiB free staging space.

Only missing individual archive .index metadata from pinned verified CDN config
is requested. Official EU cdns/versions metadata checks advertised approved HTTPS
server; pinned target is never updated/substituted. This may be an OLD build.
No credentials, telemetry capture, game-content downloads, decryption, game
execution, CASC writing, patch chain, rollback or full update engine.

Per run: <=128 requests, <=64 MiB response bytes (includes EU metadata),
per index <8 MiB including overrun probe; EU metadata <256 KiB each.
Redirects/compressed responses rejected. HTTP/TLS overhead and network buffering
are not included in response-read caps. TLS certificate verification remains on.
Sequential; no automatic retry; stop first request/verification failure.
Requests have 30s blocking timeout and 90s loop deadline (blocking read may extend
wall-clock deadline). Cancellation cannot instantly interrupt a blocked read.

Every cached/downloaded index is validated: footer filename hash, footer checksum,
TOC checksum, all block checksums, record order, padding and offset bounds.
Existing invalid files are preserved and not overwritten; report partial.
Group index is NOT downloaded, repaired or deleted. Valid normal indexes provide
fallback for the v0.10 planner. Do not delete invalid files to force success.

Progress resume is by complete verified files: rerun skips these after validation.
Interrupted response discarded; no byte-range partial transfer resume.
Successful new indexes are added only to previous staging cache, never game.
If all normal indexes valid, original offline v0.10 planner is run automatically.
Other remaining gaps (loose index, content mapping, local unverified payloads)
are still reported. Complete index coverage is not proof of HTTP availability,
actual patch size, minimal playable data or a successfully updated game.

Output Index-Completion-*/Retail-Index-Completion-to-share.json.
If offline replan finishes, Retail-Full-Plan-to-share.json is copied alongside.
Share only these reports. Paths/keys and derived SQLite stay LOCAL.
If cache scan is cancelled early, remaining_normal_indexes means not established
valid during this run, not all actually missing files.

Tests are synthetic and offline cached official index regression in Linux.
Actual Windows runtime, network download on user's system and full user cache
have NOT been tested by the builder. TEST-RESULTS.json records exact coverage.
Reference: https://wowdev.wiki/TACT ; https://wowdev.wiki/CASC
