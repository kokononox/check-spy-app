WoW Retail EU Larger Archive Range Pilot v0.18 — STAGING ONLY

Close WoW/Battle.net and other queue tools. Extract OUTSIDE game. START.cmd.
Python3.9+64-bit with tkinter/sqlite, no pip/admin.
Select ORIGINAL v0.9 Retail-Archive-Batch-to-share.json in CDN-Batch-* in old
staging, then installed .build.info. Keep all old caches. Needs2 GiB free staging
for fresh offline plan; preparation may take minutes.

One smallest eligible archive-range candidate >=1 MiB and <4 MiB encoded,
<=16 MiB decoded, from fresh verified metadata/index plan. Incomplete plan stops.
No candidate within caps -> explicit no-request result. No silent size increase.
Private imported SQLite not trusted; original offline planner generates new DB.

At most ONE archive asset request and4 MiB response bytes including one overrun
probe. Two official EU metadata responses before first NEW request (<256 KiB each),
HTTP/TLS overhead and network buffering additional. Pinned target never switched.
HTTPS exposes IP/transport metadata; no credentials. TLS verification ON.
Archive response must206 with exact requested Content-Range and total>end.
HTTP200 full archive rejected BEFORE body read; redirects/compression/wrong length/
truncation/oversized payload rejected. No direct fallback, retry, alternate host,
protection bypass, decryption or game keys. Stop and report on first failure.

Fully verify exact EKey and chunk hashes; full decoded CKey when supported.
Opaque content may have encoded integrity only; never claim it decoded/decrypted.
Decoded game bytes only hashed, never saved/executed. Only successfully verified
encoded sample saved to Large-Range-v018/<build-key>/objects.
Re-run revalidates existing complete sample and reuses it without new HTTP; exact
previous v0.12-v0.17 encoded files may also be verified and locally imported.
Report separately flags Range requested, strict headers checked, exact response
length received and content integrity. Cached reuse does NOT prove new Range.
Invalid existing file preserved, not overwritten. No partial-byte resume.

30s blocking timeout /90s read loop deadline; blocked read can extend wall-clock.
Cancellation may wait for timeout; wait for final report before closing.

Share ONLY Retail-Large-Range-to-share.json from Run-* shown in GUI. Keep
range-private.json, EKeys/paths, private SQLite and blobs LOCAL.
Original game files unchanged. No CASC writer, installer, binary patch chain,
rollback, playable update or all-archive availability claim. Single pilot only.

Tests synthetic/mock under Linux. Actual Windows runtime and LIVE larger archive
Range in this version NOT tested by builder. TEST-RESULTS.json exact coverage.
Reference https://wowdev.wiki/TACT ; https://wowdev.wiki/BLTE
