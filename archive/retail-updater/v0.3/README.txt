WoW Retail EU Read-only Inventory 0.3
NOT an updater, complete delta planner, or minimal patch-size calculator.

Extract outside the game. Close WoW and Battle.net. Run START.cmd normally.
Select the ORIGINAL successful Retail-Staging-to-share.json from v0.2's staging
folder (beside build.config/cache), then select .build.info from the installed game.
This comparison is pinned to the target of that v0.2 report, not silently switched
to a later build. The latest version observed is separately recorded.

No native TACTTool rerun, game downloads, process attachment or original-game writes.
Reuses a cached download manifest if present. Otherwise downloads ONLY the target
DL manifest (~61 MiB for 12.1.5.70391), verifies decoded size/content hash and caches
it inside staging. Does NOT redownload all 850 MB of the prior tool's metadata.
Normal HTTPS certificate verification. No local metadata is sent to the server.
Existing Python 3.9+ 64-bit with tkinter/sqlite is required; no extra pip packages.
Large binary parsing/SQL can take minutes and require several hundred MB of RAM
and staging disk space. At least 1 GiB free space is required. No exact total runtime or remaining-time estimate promised.
Cancel is checked between requests/batches, not instant during a blocked HTTPS read
or SQL aggregation. Close the window only after the stopped message.

Scope: Windows x64 EU, recognized locales from existing metadata, speech/text,
all download priorities and optional tags. Shared untagged objects are included.
Counts/encoded sizes are deduplicated by full target EKey. Target tag groups are
matched by intersection within each group and AND across groups.
Local indexes: structural support is limited to version 7, sizes 4/5/9, offsetBits30.
All readable journal generations are considered, not shmem-selected active journals.
Matches are ONLY 9-byte EKey prefix + encoded size with archive reference in bounds.
Index checksums and archive payload hashes are NOT verified. A candidate may be
stale/corrupt. No observed match is NOT proof that the full object is absent.
Unsupported/missing buckets/references are reported; do not interpret partial
coverage as complete installation inventory. Changes to source journals/archives
or .build.info during the scan abort final results.

Full object byte totals are NOT binary patch sizes. Alternate reusable encodings,
content-level reuse, patch chains, encrypted content, required minimum assets,
complete CASC writing, transactional installation and rollback are not implemented.
The tool cannot make Incompatible realms playable.

Output: new Inventory-* directory in staging. Share ONLY Retail-Inventory-to-share.json.
Keep inventory-private.sqlite and cached manifests LOCAL. No personal paths,
account/geolocation tags, tokens or TLS keys are included in the shareable report.
No need to upload your entire Data folder. Do not delete the previous cache.

References: https://wowdev.wiki/CASC and https://wowdev.wiki/TACT
Parser approach checked against TACTSharp c12f9fa (CASCIndexInstance.cs).
Real target DL manifest parsing and synthetic local index/SQL tests were performed
in Linux. Actual Windows UI/local game journal compatibility remains unverified.

Reference project MIT license included as LICENSE-REFERENCE-TACTSharp.txt.
No native TACTTool executable or TACTSharp DLL is bundled in v0.3.
