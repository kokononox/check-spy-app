WoW Retail EU Offline Global Candidate Plan v0.10 — NOT an installer/full updater

Close WoW and Battle.net. Extract OUTSIDE game. Run START.cmd normally.
Choose ORIGINAL v0.9 Retail-Archive-Batch-to-share.json in its CDN-Batch-* folder,
then installed .build.info. Keep the entire earlier staging/cache tree.
Existing Python 3.9+ 64-bit with tkinter/sqlite only. No pip/admin/drivers/native EXE.
At least 2 GiB free staging required for derived private SQLite/metadata. Local scans
may take minutes and several hundred MB RAM; exact remaining time is unavailable.

ZERO network requests. No downloads, game directory writes, injection, execution,
key extraction, decryption or installer. Missing metadata is NOT silently downloaded.
Pinned target from prior successful v0.2 + v0.9 report; current version online is NOT
checked. Installed version changes or disagreeing reports stop to avoid stale mixing.

Reads fully hash-verified cached target Download + Encoding manifests. Can decode
already cached encoded METADATA into a new Full-Plan-* output if decoded cache is
missing. Never saves newly decoded GAME assets. Requires existing cache, not internet.
Same v0.3 scope: EU Windows x64, identified installed locales, all priorities and
optional tags; shared untagged records included. NOT minimum playable/optional choice.
Deduplicates target full EKey, independently reconciles global counts and byte sums.

Fresh local .idx references: 9-byte EKey prefix + encoded size + archive bounds ONLY.
These are CANDIDATES, not full payload integrity or proof of safely reusable content.
All historical journal generations, not shmem-resolved active generation. Local .idx
checksums and actual contents of matching game assets are NOT validated by this step.
Detailed target CKey + cached CDN/staging analysis covers ONLY fresh unmatched
prefix/size candidates, not every matching object in the entire installed game.

CDN catalog: pinned target CDN config must be cached. Reverify group index if valid;
otherwise scan ALL existing configured individual normal indexes. No network fallback.
Conservative TACT v1: hashBytes8/keyBytes16/sizeBytes4; offsets 4 archive, 6 group,
0 loose-file index. Full footer-name/checksum, TOC, ALL block hashes and ALL record
order/bounds verified before accepting any locations from that index.
Limits: normal index8MiB, group/loose128MiB, 20 million records/index, <=1 million
matching locations/index. Missing/unsupported/invalid indexes are coverage gaps,
not proof of absent objects or a broken whole installation. Invalid group cache
is not deleted/replaced; valid normal indexes can still independently be used.
Index location = metadata evidence, NOT tested HTTP206 availability for every object.
Loose entry = advertised direct object, NOT guaranteed response200 (prior403 relevant).

Already staged EXACT target encoded representations: reverify full EKey/chunk hashes,
size and decoded CKey for supported N/Z/raw; E/unsupported remains encoded-only.
Only these VERIFIED target representations reduce the unmatched transfer-candidate sum.
No old alternate encoding substitution. Existing decoded-only Wow.exe.bin may match
CKey and decoded size, but is observed SEPARATELY, never subtracted without exact
re-encoding/target compatibility. Never execute or copy it into installed game.
Staging scan <=5000 known sample/cache files, per encoded/raw file512MiB; decoder
limit2GiB. Oversized/unreadable/out-of-scope files create explicit partial scan flags.
Repeated copies deduplicated by full exact target EKey; no double-counting samples.

Output: new Full-Plan-*/full-plan-private.sqlite + Retail-Full-Plan-to-share.json.
Private DB contains identifiers/paths; keep it LOCAL. Share ONLY the JSON report.
Whole-object totals are NOT required download, binary patch, compressed bundle,
minimal playable size, guaranteed savings or proof every other file is valid.
Remaining unknowns include local payload integrity, incomplete catalog/staging scope,
patch chains, re-encoding, HTTP availability, installation/CASC writer and rollback.
"Completed" means the defined offline planning steps ran, NOT a full valid updater.
A partial-coverage report is still useful; do not delete caches to force a clean result.
Failure/cancellation may leave an incomplete PRIVATE DB; no final successful report.
Normal running never modifies original caches, samples, reports or game files.

See TEST-RESULTS.json: Linux synthetic/real public metadata tests are not actual
Windows interface execution or validation of your private installation/cache.
References: https://wowdev.wiki/TACT https://wowdev.wiki/CASC https://wowdev.wiki/BLTE
No game files/vendor binaries bundled. Reference MIT license text included.
