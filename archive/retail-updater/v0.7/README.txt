WoW Retail EU Limited CDN Pilot v0.7 — NOT an updater or installer

Close WoW and Battle.net. Extract OUTSIDE installed game. Run START.cmd normally.
Select ORIGINAL v0.6 Retail-Payload-Diagnostic-to-share.json beside
payload-verify-private.sqlite, then installed .build.info. Keep caches/staging.
No database upload, new pip packages, Administrator, injection or native EXE.
Needs existing Python 3.9+ 64-bit with tkinter and sqlite3.

Preflight verifies the cached target Encoding metadata, chosen CKey/EKey/size,
original report/database counts and current installed version. Reads only local
metadata (not game assets). Queries official EU versions and cdns HTTPS endpoints,
response read capped at 256 KiB each; then shows plan for user confirmation.
Selects the smallest target object below 8 MiB among v0.6 encrypted-only candidates.
Only the EXACT target EKey is requested, not the old alternative representation.
Shows pinned and current online versions; NEVER silently advances target. An
outdated pinned target can still be a transport test, not a latest update.

ONE game-data request from currently advertised https://level3.ssl.blizzard.com.
No HTTP, redirects, automatic retries, archive download or fallback. Reads at most
8 MiB of asset response, including overrun detection. HTTP/TLS overhead and small
metadata responses are additional, so this is NOT a total-network-byte guarantee.
Timeouts and a bounded transfer deadline apply. Cancel may wait for socket timeout.
A 404 means this direct object was not available; it may still be in a CDN archive.
Archive index / range fallback is NOT implemented. Failure is explicitly reported.

Full encoded integrity: expected EKey (chunked header plus every chunk MD5, or
entire chunkless/raw object), expected size; decoded CKey for supported N/Z/raw.
Encrypted/unsupported chunks remain undecoded. No encryption keys are used,
extracted or supplied. Decoded assets are hashed in memory only and never saved.
No credentials or personal tags sent, but CDN necessarily observes your IP and
normal connection metadata. No account login required.

New staging folder CDN-Pilot-* only. Verified encoded bytes kept as
verified-target-sample.blte; never execute or copy manually into game.
Only this run's incomplete sample.part is deleted on failure. Original files,
caches, reports and private databases are preserved. No writes to game directory.
Share ONLY Retail-CDN-Pilot-to-share.json. No sample contents/private paths in report.

Still missing: full update selection, patch chains, archive-range fallback,
CASC writer, installation, rollback and game compatibility/runtime testing.
No claim of saved bandwidth or playable updated game from this sample.
Linux synthetic and public-CDN QA is not a real Windows installation test.

Format references: https://wowdev.wiki/TACT https://wowdev.wiki/BLTE
Existing MIT reference license included. No game files bundled.

LIVE QA NOTE: Official metadata requests succeeded. A tiny selected data-object
request returned HTTP 403 and no sample body was obtained; that actual target
asset download/verification is NOT claimed successful. A known-object HEAD
request returned 200 with no body read. User Windows candidate may differ.
Do not interpret 403 as proof of global CDN failure or missing archive content.
