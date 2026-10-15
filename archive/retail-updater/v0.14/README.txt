WoW Retail EU Single Direct Pilot v0.14 — STAGING ONLY

Close WoW/Battle.net. Extract OUTSIDE game. Run START.cmd.
Python 3.9+ 64-bit with tkinter/sqlite; no pip or Administrator.
Choose ORIGINAL v0.9 Retail-Archive-Batch-to-share.json inside CDN-Batch-* in old
staging, NOT the chat copy. Then installed .build.info. Keep all old caches.
Needs2 GiB free staging for fresh offline plan; may take minutes before request.

Uses existing checksum-verified metadata and fully validated indexes to rebuild
fresh offline plan. Partial plan stops sampling. Does not trust an imported
private SQLite. Chooses ONE smallest eligible direct-only target representation.
Encoded size must be <4 MiB, reserving one response overrun-probe byte; decoded
size <=16 MiB unchanged from v0.12. Objects exceeding these caps are not selected.
No claim that this tests every direct object or fully updates the game.

At most ONE asset request and 4 MiB asset response bytes including probe.
Two official EU cdns/versions responses (each <256 KiB), network buffering and
HTTP/TLS overhead are additional. No index/config/game-archive download.
Current approved official HTTPS server must be advertised; pinned historical
target NEVER substituted. Current online version reported but may differ.
HTTPS exposes IP and transport metadata to contacted servers; no credentials.

Direct response must be200, identity encoding and exact size (Content-Length
if supplied). Redirects/compressed/mismatched/truncated/oversized responses
rejected. Stop on first failure.403 reported, NOT bypassed. No alternate host,
archive fallback or automatic retry. TLS certificate verification stays ON.
Blocking timeout30s, loop deadline90s (blocked reads may extend wall-clock time).
Cancellation may wait for network timeout; wait for final report before closing.

Verify full EKey/chunk hashes and full decoded CKey when supported. Opaque
content may have encoded integrity only; NOT claimed decoded or decrypted.
Decoded game bytes never saved or executed. Only successfully verified encoded
sample saved to staging Direct-Sample-v014/<pinned-build-key>/objects.
Existing complete sample reverified and reused on rerun; no asset request then
(two small official metadata checks still happen). Interrupted response discarded;
no partial byte resume. Existing invalid sample preserved, not overwritten.
The inherited planner does not subtract this separate pilot cache.
Source changes can change selected sample; no guaranteed reuse across new builds.

Share ONLY Retail-Direct-Pilot-to-share.json from Run-* shown in the GUI.
Keep sample blobs, paths, identifiers and private SQLite local.
No game install/CASC writer, binary patch chain, rollback, decryption, key
extraction or game execution. Game installation files remain untouched.

Tests are synthetic under Linux. Actual Windows runtime and live direct CDN
access in this version NOT tested by builder. See TEST-RESULTS.json.
Reference https://wowdev.wiki/TACT ; https://wowdev.wiki/BLTE
