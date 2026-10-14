WoW Retail EU Archive Range Pilot v0.8 — NOT a full updater/installer

Close WoW and Battle.net. Extract OUTSIDE installed game. Run START.cmd normally.
Choose ORIGINAL v0.6 Retail-Payload-Diagnostic-to-share.json beside its private
payload-verify-private.sqlite, then installed .build.info. NOT the v0.7 report.
Keep earlier folders/cache. No uploads of databases or game files are required.
Existing 64-bit Python 3.9+ with tkinter and sqlite3 only; no pip/admin/drivers.

Reads the pinned target Encoding and chooses one smallest encrypted-old-alternative
candidate with exact target encoding smaller than 8 MiB. Reconciles report/DB and
metadata hashes. Uses the original target CDN config hash, not a guessed version.
Checks current official CDN/versions (small metadata); shows pinned/current versions.
Does NOT silently advance target, install, write CASC, inject, decrypt or execute.

Index lookup: use the existing locally generated target archive-group .index,
then cached normal target .index files. CDN group indexes are NOT downloaded.
Supported conservative v1 format: keys16, hashBytes8, sizeBytes4, offsets4 or6.
Verifies footer-name MD5, footer checksum, TOC checksum, ALL block checksums,
used blocks' key order and exact key+size match. Group references bound to pinned
CDN config archive list. Unsupported/damaged indexes are reported, not blindly used.
Original caches/game files remain read-only. New files only in CDN-Range-* staging.
If missing: fetch at most 16 individual small indexes with aggregate response-read
budget 32 MiB, per-index limit 2 MiB. Config/official EU metadata are additional
small responses capped at 256 KiB each. At least ~41 MiB free staging required.
Incomplete index search is NOT proof of absent content. No unbounded auto-fetch.

After a location is found, shows sample size and asks BEFORE fetching game data.
Only ONE exact Range request, at most 8 MiB response read, no automatic retry.
Requires HTTP 206 + exact Content-Range start/end + matching length when provided.
A full archive HTTP 200 is rejected BEFORE its body is read. Normal socket/network
buffering and HTTP/TLS overhead are outside response-byte limits; not a total traffic
meter. Never downloads a whole archive as fallback. Redirects and HTTP rejected.
Timeouts/cancel checks apply; stopping can wait for current socket timeout.

Checks exact downloaded target EKey/chunk MD5s and encoded size; decoded CKey
for supported N/Z/raw only. E/unsupported modes remain undecoded, separately marked.
Decoded assets are hashed in memory, not saved. No keys extracted or supplied.
Keeps verified-target-range-sample.blte OUTSIDE game only; NEVER run or copy to game.
Only this run's incomplete range-sample.part is deleted after failure.
Normal HTTPS exposes IP/transport metadata to contacted servers; no credentials/tags.

Share ONLY Retail-Archive-Range-to-share.json, including failure/lookup-limit results.
No private paths, account identifiers or asset contents in public report.
Metadata lookup failures after output folder creation get a diagnostic report.
Invalid original inputs / preflight failures can stop before a report is created.

Still no full update selection, binary patch chains, CASC installation writer,
rollback or playable updated-game guarantee. Windows/runtime user data untested
until you run this version; see TEST-RESULTS.json for exact QA outcomes.
References: https://wowdev.wiki/TACT https://wowdev.wiki/BLTE
No native TACTTool or game asset is bundled. Reference MIT license included.
