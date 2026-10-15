WoW Retail EU Controlled Stop/Resume Test v0.17 — STAGING ONLY

Close WoW/Battle.net AND previous queue tools. Extract OUTSIDE game. START.cmd.
Python3.9+64-bit with tkinter/sqlite, no pip/admin.
Choose ORIGINAL v0.9 Retail-Archive-Batch-to-share.json inside CDN-Batch-* from
old staging, then installed .build.info. Keep all v0.12/v0.14/v0.15/v0.16 caches.
Needs2 GiB free staging; offline metadata/cache verification can take minutes.

TWO-STAGE controlled acceptance test, not full progressive download:
1. FIRST run reverifies old files, excludes complete ones, selects NEW bounded
   batch and deliberately PAUSES after TWO newly completed encoded objects.
   This is INTENTIONAL, not a connection failure. Completed files/state preserved.
2. SECOND run resolves SAME previous batch IDs against fresh verified metadata,
   checks those complete files and requests ONLY remaining objects. No second
   planned pause. If a real error occurs, progress preserved for later diagnosis.
3. After batch fully complete, further runs download NO next batch.
   No phase reset button or automatic return to mass download.
Send ONLY each Run-*/Retail-Controlled-Resume-to-share.json. Keep private state,
queue-private.json, private SQLite and blobs LOCAL. Do not erase caches.

Requires at least3 eligible selected objects so pause leaves something to resume;
otherwise reports preparation blocker without requesting game data.
Max8 objects /16 MiB asset response bytes including overrun probes per run.
Per encoded object<4 MiB, decoded<=16 MiB. Two official EU metadata responses
before first new object (<256 KiB each), HTTP/TLS overhead/network buffering
additional. Pinned historical target never silently replaced. HTTPS exposes IP,
no credentials sent. TLS verification ON, redirects/compression/wrong sizes rejected.
Archive206 exact Range; full-archive200 rejected before body; direct200.
First real error stops; no retry, bypass, alternate host, decryption or key lookup.

State under Queue-v017/<build-key>/progress-private.json, objects under objects.
v0.16 source cache read/verified but NOT altered; v0.17 maintains separate state.
Persistent EKeys are hints only: sizes/locations/content supplied by freshly
checksum-verified metadata. "Completed" flags never replace actual hash checks.
If interruption happens BEFORE planned pause, next run finishes reaching two
cumulative completed active objects before pausing. A missing pause marker with
>=2 actual complete files is recovered and recorded as such, not blindly trusted.
No partial-byte resume: interrupted response discarded, complete files reverified.
Private report snapshots can be stale after crash; saved files rechecked.

Cache scan cap4096 files including duplicate representations; above cap stop
without network. Invalid cache/state preserved, not deleted/overwritten. Exclusive
queue.lock prevents concurrent v0.17 runs; normal exits remove OWN lock. Crash can
leave stale lock: do NOT blindly delete it or reset state, send blocker report.
Fresh source scope mismatch stops instead of silently changing prior batch.
Decoded game bytes only hashed, never saved/executed. Opaque content may remain
encoded-integrity-only; not decoded/decrypted. Original game installation untouched.
No CASC writer/installer, patch-chain, rollback or playable-update claim.

30s blocking timeout /90s read loop deadline (blocked read can extend wall-clock).
Cancellation may wait for timeout. No need to disable internet or time Stop.
This tests APPLICATION-controlled stop/resume between COMPLETE objects; it does
NOT reproduce network timeout mid-response, power-loss recovery or byte resume.

Synthetic/mock test validation on Linux; real Windows runtime and live v0.17
stop/resume NOT tested by builder. TEST-RESULTS.json exact coverage.
Reference https://wowdev.wiki/TACT ; https://wowdev.wiki/BLTE
