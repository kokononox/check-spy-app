WoW Retail EU Small Archive Batch v0.9 — NOT a complete updater

Close game/Battle.net. Extract outside game. Run START.cmd normally.
Choose ORIGINAL v0.6 Retail-Payload-Diagnostic-to-share.json beside its private
payload-verify-private.sqlite, then installed .build.info. Not the v0.8 report.
Keep original caches/private DB local. Existing Python3.9+ 64bit/tkinter only.
No pip, Administrator, native tools/drivers/injection or account login.

Selects up to 8 smallest eligible EXACT TARGET objects among old-encrypted-only
candidates in v0.6. Total selected encoded bytes STRICTLY below 8 MiB. This reserves
one possible overrun-detection byte. NOT whole update/all files/playable selection.
Reconciles report/DB, full target Encoding metadata hash and selected CKey/EKey/sizes.
Uses pinned build/CDN configs, not guessed latest. Current version displayed;
if different, no silent target switch. Metadata preflight can fail before output.

Prefer existing generated group/normal index caches. Checks full footer/name/TOC/
all block hashes and used block order before trusting exact key+size/offset.
Missing normal indexes: at most 16 actual requests and 32 MiB response-read budget
SHARED across whole batch, not per sample. Individual index <=2 MiB. Reuses indexes
saved into this run's staging. Does not redownload the same missing archive index
within this batch. Cached validation counts are operations, not unique file counts.
Two small EU metadata responses and at most one missing CDN config response (each
<256 KiB) are additional. Some targets can remain unresolved under lookup limits;
that is NOT proof that content is globally absent. Reports every selected object.

After lookup, UI shows located count and exact combined bytes and requests approval.
Downloads located samples sequentially into NEW CDN-Batch-*/Sample-*/ only.
Requires HTTP206 and exact Content-Range. Rejects full archive 200 BEFORE body read.
Game-data response read capped at 8 MiB across ENTIRE batch. Socket buffering and
HTTP/TLS overhead are additional, so this is NOT a total-network-traffic guarantee.
HTTPS only, no redirects, automatic range retries or full-archive fallback.
Cancel may wait for current socket timeout; local metadata scans can take minutes.

Each sample: full exact EKey/chunk MD5+size verified; full decoded CKey for N/Z/raw.
Encrypted/unsupported target chunks are encoded-integrity only, separately counted.
No keys, decryption or plaintext asset output/execution. Encoded samples kept only.
Stop at first download/verification failure; retain previously verified files.
Do NOT run/copy staging samples into installed game. No CASC writer/installation.
Only own incomplete sample is deleted on error, never prior successful outputs.
No automatic resume: a new run makes a new folder and may repeat downloads. Share
report after an error; don't rerun repeatedly without reviewing the result.

Share ONLY top-level Retail-Archive-Batch-to-share.json. Contains per-sample outcome,
reconciled object counts/bytes, partial lookup warnings, and hash verification flags.
Subfolder diagnostics and all private metadata/databases stay local.
No original cache/game files changed; no personal account tags or credentials sent.
Normal HTTPS does expose your IP/transport metadata to the contacted CDN endpoints.

Still missing: full update planning, binary patch chains, CASC installation writer,
rollback, runtime compatibility and a guaranteed updated playable game.
TEST-RESULTS.json separates synthetic/public CDN tests from real Windows testing.
References https://wowdev.wiki/TACT https://wowdev.wiki/BLTE
No game assets or native TACTTool binaries bundled. Reference MIT license included.
