WoW Retail EU Local Payload Diagnostics v0.6 — NOT an updater

Close WoW and Battle.net. Extract outside the game. Run START.cmd normally.
Select ORIGINAL Retail-Content-to-share.json from v0.4 beside content-private.sqlite,
then the installed game's .build.info. Keep earlier folders/caches/private databases.
Never upload the database or whole Data folder.

Zero network requests. No game-file downloads, CASC writes, injection or execution.
Reads metadata and actual candidate asset bytes only from local archives. Decoded
GAME ASSETS are hashed as a stream and are NEVER saved or executed. Derived Encoding
METADATA may be written only into a new staging output directory if cache recovery
is needed. All original installation/cache files remain unchanged.
Existing Python 3.9+ 64-bit + tkinter/sqlite. No new pip packages or Administrator.
At least 1 GiB free staging space required. May read several hundred MB of metadata
plus candidate payloads and take minutes. No exact runtime estimate is promised.
Cancel checks occur between chunks/records; wait for the stopped message.

Population: ONLY alternate-encoding same-content candidates from v0.4. This does
NOT validate the entire game or the other unmatched assets. Source report/private
DB counts reconcile. Target/installed Encoding metadata is re-verified and bindings
are checked against current local build info. Target is pinned, not checked online.
Fresh local journals locate candidate data; all historical generations are considered.
Active journals and index checksums remain unresolved. Bounds/coverage errors reported.

Validation: full expected alternate EKey (BLTE header+chunk hashes, or whole encoded
file for chunkless BLTE), decoded size and full CKey for N/Z or raw-unencoded content.
Encrypted E, LZ4 mode 4, recursive F or unknown compression modes are NOT decoded in
this version. Their encoded integrity can still be checked; they are NOT labelled
fully content-verified. No encryption keys are extracted or protection bypass attempted.
Per-asset limits: encoded <=512 MiB, decoded <=2 GiB; larger objects are reported
as NOT CHECKED, not corrupt. Multiple indexed locations are tried up to a bounded
ambiguity limit. Repeated identical local alternatives are hashed once and reconciled
per target object. No conclusion of global corruption/absence from one failed location.

content_verified = decoded content/CKey AND encoded representation integrity checked.
encoded_integrity_only = opaque representation checked, decoded CKey still unverified.
Other classes distinguish invalid candidates, missing indexed locations, I/O errors,
metadata mismatch and size-limit skips. Complete means the test ended, not all passed.

IMPORTANT: verified old content is NOT an installed update or guaranteed saved bandwidth.
If the target Encoding table does not advertise the older representation, a future
re-encoding/compatibility strategy may be needed. Target-advertised alternative is a
metadata observation, NOT a tested guarantee the new game selects/accepts that copy.
No installation writer, patch chains, minimal playable/optional selection or rollback.

Output: new Payload-Verify-* folder under staging. Share ONLY:
Retail-Payload-Diagnostic-to-share.json
Keep payload-verify-private.sqlite and all metadata local. Report includes no private
paths, account/geolocation tags, tokens, TLS secrets or decoded asset contents.

References: https://wowdev.wiki/TACT https://wowdev.wiki/BLTE https://wowdev.wiki/CASC
Reference project MIT license included. No native TACTTool/DLL is bundled.
Actual Windows/user-archive verification remains to be tested on your machine.

NEW: reason_summary and encoded_only_mode_combinations distinguish E/encrypted,
4/LZ4, F/nested BLTE and unknown outer markers. Mixed-mode objects are one
exclusive combination, not double-counted. E only identifies outer encryption;
its inner compression/content remains unknown. No new decoder is included yet.
Choose the ORIGINAL v0.4 content report again, NOT the v0.5 payload report.
This rechecks existing local data; earlier outputs are preserved.
