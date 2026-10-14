WoW Retail EU Version Check v0.1
THIS IS NOT AN UPDATER. No TACTTool/TACTSharp integration is implemented yet.
Windows: Extract this ZIP outside the WoW installation, then run START.cmd.
Select the exact .build.info file in your WoW installation root.
Requires your existing Python 3.9+ with tkinter; no pip packages or administrator access.
Reads installation metadata only. Sends an ordinary HTTPS GET to the official EU
versions endpoint, with normal certificate verification. Sends no local metadata.
Does not download game files, modify installation metadata, inject into processes,
read credentials or bypass protections. No claim of realm compatibility or integrity.
Optional shareable JSON report must be saved outside the installation.
The external service can change or become unavailable; a failed check is not evidence
that your installation is current. A version mismatch is not a completed update.
EU Retail Windows x64 only. Does not select US/PTR/Classic builds.
Source: https://wowdev.wiki/Ribbit
Windows UI and actual Windows networking have not been tested by the author here.
