WoW Retail EU Offline Content Comparison 0.4
NOT an updater or confirmed minimal patch-size calculator.

Close game and Battle.net. Extract this package outside the installation.
Run START.cmd normally. Select ORIGINAL Retail-Inventory-to-share.json from v0.3
beside inventory-private.sqlite. Then select the installed game's .build.info.
Keep all earlier staging folders and private databases on YOUR computer.
Do not upload the database or entire Data folder.

Zero network requests and zero game downloads. Uses Encoding metadata already
cached by v0.2, plus installed local build config/Encoding metadata. If unavailable,
it stops with a precise error instead of silently re-downloading 850 MB.
No TACTTool/Frida/process attachment, administrator access or extra pip packages.
Requires existing Python 3.9+ 64-bit + tkinter/sqlite. Allow at least 1 GiB free
staging space and several hundred MB of RAM. Metadata hashing/parsing can take
minutes; exact total/remaining runtime is not promised. Cancel checks occur between
file/chunk/record/SQL operations; wait for the stopped message before closing.

Input population: ONLY target EKeys unmatched by prefix+encoded-size in v0.3.
Target is pinned to that report; no online latest-version check is performed.
Installed build must still match the inventory. Fresh local indexes are read.
Verified target/installed Encoding tables map CKey -> alternative EKeys and sizes.
Matching CKey + decoded size identifies the SAME advertised file content. An
alternative indexed EKey prefix+encoded-size candidate is required for the class
"alternate_encoding_same_content_candidate". CKey existing in old-build metadata
alone does NOT establish that its asset is installed on disk.

Metadata validation: full decoded content hash, BLTE EKey/header/chunk hashes for
encoded sources, Used Encoding page checksums and page-index consistency. Metadata can
be decoded using only supported N/Z compression; encrypted/unsupported metadata
is refused. No protection bypass or secret extraction. Metadata is not executed.
OTHER GAME ASSET PAYLOADS ARE NOT YET READ/HASH-VERIFIED. Candidates may still be
stale/corrupt. All readable journal generations are used, not shmem-resolved active
journals. Local journal checksums remain unverified; coverage errors are reported.

Whole-target-object encoded byte sums are NOT confirmed download/patch sizes or
saved bandwidth. Alternate encoding reuse may need a future installation strategy;
this tool does not promise that a new client accepts every older representation.
Loose-file content, other builds, binary patch chains, optional/minimal playable
selection, CASC writing, installation transaction and rollback are NOT implemented.
No .build.info or original game data is changed. The tool cannot make realms playable.

Output: new Content-* folder under staging. Share ONLY Retail-Content-to-share.json.
Keep content-private.sqlite and local/target-encoding.decoded metadata local.
No source paths, account/geolocation tags, credentials or TLS secrets in share report.

Refs: https://wowdev.wiki/TACT and https://wowdev.wiki/CASC
Encoding parser approach checked against TACTSharp c12f9fa/EncodingInstance.cs.
Real official target Encoding parsing and synthetic alternate-encoding fixtures
are tested in Linux. Actual Windows local Encoding extraction remains untested.

Reference MIT license is included; no native TACTSharp DLL/TACTTool EXE is bundled.
All 11 controlled tests and official target metadata parsing passed in Linux.
