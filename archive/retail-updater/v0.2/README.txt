WoW Retail EU staging test v0.2 — NOT a complete updater
1. Extract this package OUTSIDE the game installation. Run START.cmd normally.
2. Select the installed game's .build.info; review the current EU target.
3. Approve the one-file test and choose a separate staging folder.
Never run or copy the sample into your game. Verified output is saved as
verified-Wow.exe.bin to reduce accidental execution. It is NOT an installed update.
Share ONLY Retail-Staging-to-share.json. Keep TACTTool-private.log local.
Requires existing Python 3.9+ with tkinter and Windows x64. No pip dependencies.
Bundled TACTTool is the upstream alpha 0.2.0-alpha1 Windows x64 release (MIT),
not compiled by this project. Its EXE is checked against the bundled integrity pin.
Official HTTPS version/CDN discovery and normal certificate validation are used.
Build config and decoded install manifest content hashes are checked. The sample
is selected using EU/Windows/x64 manifest tags and extracted by CKey, not by name.
Output size and MD5 content key are checked independently after TACTTool returns.
SHA256 of the final sample is recorded; this is NOT Authenticode verification.
No Battle.net credentials, tokens, local account tags, process injection or protection
bypass. TACTTool gets NO --basedir and never receives the installed game's path.
All native-tool cache/log/output files go into a new staging run directory.
No CASC writing, complete manifest download/update, patch application, rollback engine,
installed-file integrity check or realm-compatibility check has been implemented.
Metadata can exceed hundreds of MB even for one ~80 MB sample. Allow 2 GiB free space.
No accurate progress percentage or cross-run download resumption is promised.
Timeout 20 minutes. Cancel stops the native download; partial files remain in staging.
Cancellation during small metadata requests is delayed until those requests finish.
A nonzero exit, missing output, wrong hash or size is treated as failure, not success.
Release source: https://github.com/wowdev/TACTSharp/releases/tag/0.2.0-alpha1
Architecture: https://wowdev.wiki/NGDP
License: vendor/LICENSE-TACTSharp.txt
Actual Windows native execution has NOT been tested by the author here.

Linux live CKey extraction, independent raw-manifest checks and 13 local tests passed.
These do NOT establish that the Windows UI/native execution works on your machine.
