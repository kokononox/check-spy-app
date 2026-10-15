WoW Retail EU Small Resumable Route Samples v0.12 — STAGING ONLY

Close WoW/Battle.net; extract outside game; run START.cmd.
Python 3.9+ 64-bit with tkinter/sqlite, no pip/admin.
Select ORIGINAL v0.9 Retail-Archive-Batch-to-share.json in CDN-Batch-* in previous
staging; NOT a chat-downloaded report. Then installed .build.info.
Keep the completed v0.11 staging/cache; 2 GiB free space needed for derived plan.

This program rebuilds a fresh offline plan from verified cached manifests,
Encoding metadata and indexes. It does NOT trust an imported private SQLite.
Incomplete plan stops sampling. Selects smallest eligible 3 archive-route and
3 direct-only target objects, each <=1 MiB encoded /16 MiB decoded, at most6.
Only target candidates mapped to exact verified metadata are eligible; existing
exact staged copies known to the inherited planner are excluded.

Sequential: archive route first, direct second. First failure blocks remaining
samples in THAT route; the other route may still run. No bypass, alternate host,
credentials, retries, game keys or decryption. Direct 403 is recorded, not solved.
Range requires206 with exact Content-Range; full-archive200 rejected BEFORE body
read. Direct requires200. Redirects/compression/mismatched Content-Length rejected.
TLS certificate verification stays ON. No index download in v0.12.

At most6 asset requests, <=8 MiB asset response bytes including overrun probes.
Two official EU metadata requests (each <256 KiB) and HTTP/TLS/network buffering
are additional. Blocking timeout30s, loop deadline90s; blocked reads may extend
wall-clock deadline. Cancellation can wait for a network timeout.
Pinned target remains historical if newer version online; no silent substitution.
HTTPS exposes IP and transport metadata to the official contacted servers.

Encoded data verified using EKey +chunk hashes and, for supported N/Z/unencoded
content, full decoded CKey. Decoded bytes are only hashed, never saved/executed.
Opaque encrypted/unsupported content may have ENCODED integrity only.
Only successfully verified encoded sample files saved in separate staging cache:
Route-Samples-v012/<pinned-build-key>/objects. Original game files untouched.
No CASC writer, installer, patch-chain or rollback. Samples not a full update.

Re-running rebuilds the plan, reselects the same eligible smallest objects when
sources are unchanged, and revalidates/reuses complete sample files. Interrupted
responses discarded, no byte resume. Invalid existing sample files preserved and
reported as failures. Completed files survive later route failures/cancellation.
Sample cache is separate and NOT subtracted by the inherited global planner.
If source/game/cache scope changes, the sample selection may change too.

Share ONLY Retail-Route-Samples-to-share.json from Run-* shown by the GUI.
Private SQLite, cache objects and paths stay LOCAL. No request credentials,
payloads, account identifiers, exact EKeys or private paths in the share report.

Synthetic network/selection/verification tests in Linux; real Windows runtime
and live network download NOT tested by builder. TEST-RESULTS.json lists coverage.
Reference https://wowdev.wiki/TACT ; https://wowdev.wiki/BLTE
