# Security and evidence policy

This is experimental defensive software for inspecting software on a user's own Windows device. It must not be used to intercept another person's sessions without authorization.

Do not commit real captures, raw logs, tokens, cookies, user/account identifiers, TLS key logs, private keys, CA stores, private runtime files, or target executables. Ignore rules are defense in depth, not a guarantee; review files before publishing. Use synthetic fixtures and value-free summaries.

Certificate trust in CurrentUser Root is broader than the telemetry hostname. Runtime consent, exact host/SNI scope, upstream verification, exact-CA cleanup, watchdog and manual recovery are required. Do not disable pinning, upstream TLS validation, antivirus or device security policy to force the tool to work.

Windows 11 trust-store/ACL/process-tree/GUI behavior has not been verified live in the development environment. Do not treat Linux test success as a Windows safety certification. Verify cleanup after every test and after crashes/restarts.

A targeted GitHub secret-scanning tool call was attempted during import but was unavailable because GitHub Advanced Security was not enabled for the repository. No paid feature was enabled automatically. Local review checked selected source files for private-key payloads and known personal/profile/path markers, and excluded real evidence. This is not a comprehensive security audit or proof that all secrets/vulnerabilities are absent.

If you find a vulnerability, do not attach real credentials or private captures to a public issue. Provide a minimal synthetic reproduction and sanitized details only.
