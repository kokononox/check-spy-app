WoW Retail EU Offline Direct Eligibility Audit v0.13

Close WoW/Battle.net. Extract OUTSIDE game folder. Run START.cmd.
Existing Python 3.9+64-bit with tkinter/sqlite, no pip/admin.
Choose ORIGINAL v0.9 Retail-Archive-Batch-to-share.json inside CDN-Batch-*, then
installed .build.info. Keep whole prior staging tree with completed v0.11 cache.
Requires2 GiB staging for derived full plan and may take minutes.

NO NETWORK / GAME DOWNLOAD / INSTALLATION / GAME EXECUTION / DECRYPTION.
No automatic increase of old v0.12 size caps.
Fresh offline plan verifies original manifests, Encoding and archive indexes;
then audits direct-only candidates in its freshly generated readonly SQLite.
Does not trust any imported old private SQLite. Reports partial scope honestly.

Old v0.12 caps: encoded<=1 MiB and decoded<=16 MiB, BOTH required.
Four disjoint groups: eligible; encoded cap only exceeded; decoded cap only
exceeded; both caps exceeded. Totals independently checked with SQLite aggregate
and with fresh plan. Shows five smallest encoded and five smallest decoded
candidates with each object's own pair of sizes (no keys or paths).
Independent minimum encoded and decoded ranges need not belong to same object.
No throughput, direct HTTP availability, patch size, or playable update claim.

Scope is CURRENT fresh unmatched mapped direct-only candidates, not all content.
The separate v0.12 sample cache is not subtracted by the inherited planner.
Source changes may change eligibility, so this is not an assertion about every
historical run. Hash-verified metadata supplies sizes; game objects not fetched.

Output Full-Plan-*/Retail-Direct-Eligibility-to-share.json.
Share ONLY that JSON. Keep full-plan-private.sqlite and cached originals local.
Tests use synthetic databases/mock orchestration under Linux. Actual Windows
runtime and user's full installation not tested by builder. See TEST-RESULTS.json.
Reference https://wowdev.wiki/TACT ; https://wowdev.wiki/BLTE
