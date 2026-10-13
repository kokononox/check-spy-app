# Owned read-only snapshot validation

Only agent-authored reader/core and synthetic tests. No game binaries, game version hashes, real message RVAs, user traces, or private reports. Native tests read a small page allocated by the test process itself and verify that guard pages are refused. They do not attach a debugger or target a game. Passing CI does not establish game compatibility or an outgoing hardware payload.
