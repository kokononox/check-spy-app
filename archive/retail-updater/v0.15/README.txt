WoW Retail EU Bounded Resumable Queue v0.15 — NOT FULL UPDATE ENGINE

Close WoW/Battle.net. Extract OUTSIDE game; run START.cmd.
Python3.9+ 64-bit with tkinter/sqlite, no pip/admin.
Choose ORIGINAL v0.9 Retail-Archive-Batch-to-share.json in CDN-Batch-* in original
staging, then installed .build.info. Keep all previous staging caches.
Needs2 GiB free staging for fresh offline plan; preparation can take minutes.

Fresh plan from verified cached manifests/Encoding/CDN indexes, not old imported
SQLite. Incomplete plan stops queue. Selection ONLY fresh unmatched mapped
archive/direct-only candidates; excludes exact files known to inherited planner.
Up to4 smallest eligible per route, at most8 objects. Round-robin allocates budget
before archive-first execution. Each encoded object <4 MiB; decoded <=16 MiB.
Combined expected bytes plus one overrun probe per selected object <=16 MiB.
May select fewer if size caps/budget reduce eligibility. No index/config download.

Normal archive ranges require206 and exact Content-Range; full-archive200 rejected
BEFORE body read. Direct requires200. Redirects/compressed/mismatched/truncated/
oversized responses rejected. TLS verification ON. FIRST error stops entire queue;
completed verified files remain. No bypass, alternate host or automatic retry.

<=8 asset requests and <=16 MiB asset response bytes including overrun probes.
Two official EU cdns/versions checks before FIRST new request (each <256 KiB),
HTTP/TLS overhead and network buffering additional. Entirely cached/importable
queue needs no network. Pinned target NEVER substituted by current online build.
HTTPS exposes IP/transport metadata to official servers; no credentials sent.
30s blocking timeout,90s read loop deadline (blocked read may extend wall-clock).
Cancellation may wait for timeout. Wait for final report before closing.

Existing canonical queue files are fully reverified. If missing, exact files
from v0.12/v0.14 caches with same pinned build are reverified and locally copied;
originals NOT modified/deleted. Invalid existing files cause stop, not overwrite.
Only verified encoded objects saved. N/Z/raw supports decoded CKey checking;
opaque content may be ENCODED-integrity-only, not decoded/decrypted.
No decoded game assets saved, no game execution, CASC writer, installation,
patch-chain, rollback, decryption or keys. Original game files unchanged.

Persistent complete-file store: Queue-v015/<pinned-build-key>/objects.
Resume revalidates complete files; interrupted response discarded. No partial
byte-range resume. Unchanged inputs select SAME bounded queue on rerun; this
version does NOT automatically advance to next batch or download whole update.
Inherited offline planner does NOT subtract this separate queue/pilot cache.
If sources change, selection may change too.

Each Run-* has private queue-private.json selection/identifiers and a public
Retail-Queue-to-share.json progress/result snapshot, atomically refreshed after
items. Private manifest is diagnostic; resume trusts reverified files, not the
manifest. Abrupt process/power loss can leave last snapshot stale; new run checks
saved files, and an interrupted disk write may need diagnosis (no blind overwrite).

Share ONLY Retail-Queue-to-share.json. Keep private manifest/SQLite/encoded blobs
local. Run outputs can report partial progress. A completed bounded queue is NOT
all-object availability, actual patch size or a playable updated game.

Synthetic network/selection/queue tests in Linux. Actual Windows runtime/live
multi-object transfer on user's machine NOT tested by builder. TEST-RESULTS.json.
Reference https://wowdev.wiki/TACT ; https://wowdev.wiki/BLTE
