WoW Retail EU Progressive Bounded Queue v0.16 — STAGING ONLY

Close WoW/Battle.net AND other queue programs. Extract OUTSIDE game. START.cmd.
Python3.9+64-bit with tkinter/sqlite, no pip/admin.
Select ORIGINAL v0.9 Retail-Archive-Batch-to-share.json inside CDN-Batch-* in
previous staging, then installed .build.info. Keep all caches from earlier runs.
Needs2 GiB free staging; fresh offline plan and cache hashing may take minutes.

Starts with full fresh offline checksum-verified metadata plan; partial plan
stops downloads. Reverifies same-build exact encoded files from v0.12/v0.14/
v0.15/v0.16 named-object caches, deduplicates EKeys and excludes those COMPLETE
verified representations from selection. Previous cache originals unchanged.
Cache scan cap4096 files including duplicate representations; above cap stop
without request rather than claim full coverage. Invalid in-scope cache stops;
no automatic deletion/overwrite. Files outside fresh candidate scope counted
but not assumed reusable. Encoded-only opaque files not claimed decoded/decrypted.

Private persistent state contains previous active batch EKeys ONLY as hints.
Every ID resolved against fresh verified metadata; stored sizes/locations/status
are NOT trusted. Pending objects in incomplete prior batch FIRST. Once all
previous active keys have real verified files, choose NEXT smallest bounded
batch excluding all reverified known files. Selection can advance on rerun.
At most4 candidates per route/8 objects, each encoded<4 MiB /decoded<=16 MiB.
Round-robin budgets combined size+probe bytes <=16 MiB. Archive-first execution.
This is NOT whole-game download: objects outside caps remain unprocessed.
No-next-eligible result does NOT mean game is fully updated or installed.

First error stops entire queue; completed files retained. Resume by reverified
COMPLETE files, not partial response bytes. Interrupted response discarded.
No automatic retry, alternate host, protection bypass, keys or decryption.
Archive206 exact Content-Range; full-archive200 rejected BEFORE body. Direct200.
TLS verification ON; redirects/compression/wrong sizes rejected.
<=8 asset requests /16 MiB asset response bytes including overrun probes per run.
Two official EU metadata checks before first NEW asset request (<256 KiB each),
HTTP/TLS overhead and network buffering additional. Pinned historical target
never substituted. HTTPS exposes IP and transport metadata, no credentials sent.
30s blocking timeout /90s loop deadline (blocked reads can extend wall-clock).
Cancellation can wait for timeout; wait for final report.

Persistent state: Queue-v016/<build-key>/progress-private.json.
Complete-object store under objects. Run-* snapshots/private selection recorded
atomically where applicable. Resume trusts actual hash-verified files, not last
report. Only one v0.16 run at a time using exclusive queue.lock. Normal completion,
failure and cancellation remove OWN lock. Crash/power loss MAY leave stale lock;
DO NOT delete it blindly or alter state to force success. Send report of blocker.
Malformed/mismatched state is preserved and reported, not automatically reset.
If game/source scope changes, old active IDs may no longer be eligible; report
that condition rather than silently mutate old batch.

Share ONLY Retail-Progressive-Queue-to-share.json shown by GUI.
Keep progress-private.json, queue-private.json, SQLite, keys and cached blobs
LOCAL. No game assets executed; decoded game bytes never saved. No CASC writer,
installer, patch chain, rollback, minimal playable/full-update-size claim.
Inherited planner still does not subtract separate queue caches; this wrapper
handles verified-cache exclusion for progressive queue selection only.

Synthetic/mock network and orchestration tests in Linux. Actual Windows runtime
and live progressive transfer NOT tested by builder. TEST-RESULTS.json coverage.
Reference https://wowdev.wiki/TACT ; https://wowdev.wiki/BLTE
